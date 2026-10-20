"""Static checks for AI model files (open weights) before they are installed.

Nothing is loaded or executed: no pickle.load / torch.load, nothing unpacked
to disk. The format is read from the first bytes, not from the suffix, and
every file in the tree is checked whatever kind the artifact was given.

Flag codes:
    G221  MEDIUM  the tree holds a pickle-based model (.bin/.pt/.pth/.ckpt/.pkl/
                  .joblib, or a zip with a *.pkl inside). One flag per tree.
                  Always a person's call: pickle can run code when it is loaded
                  and no scanner is complete (Hugging Face says so itself).
                  A lone MEDIUM passes `fail-on: high` but blocks `--promote-to`.
    G222  HIGH    the pickle imports something that runs commands, opens
                  sockets, evals or loads code (os/posix/nt, subprocess, socket,
                  builtins.eval/exec/..., importlib, ctypes, pickle, marshal ...).
    G223  MEDIUM  the pickle imports something outside a small allow-list
                  (tensor / storage / OrderedDict / numpy array rebuilders).
    G224  HIGH    the pickle breaks off before STOP after it already imported
                  something (a loader runs the part that comes before the break).
    G225  GAP     could not be read: unknown or unparsable format, over a size /
                  time limit, encrypted zip, unresolvable import. Inspection is
                  then partial (exit 3): the gate cannot vouch for it.
    G226  HIGH    a file that is, or is named, safetensors but breaks the format
                  (bad header, duplicate keys, holes / overlaps, size mismatch,
                  or a pickle / zip under a .safetensors name).
    G227  MEDIUM  config names code to import on load (`auto_map`), companion
                  modeling_/configuration_/... .py files next to model weights,
                  or `trust_remote_code=True`. `False` does not lower it
                  (CVE-2026-5241 and others override it).
    G228  HIGH/MEDIUM  a companion .py runs something at import time: a call to
                  eval / exec / os.system / subprocess / socket / requests ...
                  (HIGH) or a read of environment / key files / base64 / marshal
                  (MEDIUM), at module level, in a class body, a decorator or a
                  default argument. Calls inside function bodies are not seen.
    G229  GGUF chat template (LOW shown; HIGH if it reaches Jinja internals),
          Keras .h5 (MEDIUM) and .keras with Lambda / custom code (MEDIUM).

What this does not do: say anything about the model's behaviour (bias, hidden
instructions, training data); look into formats not listed (ONNX, TensorFlow
SavedModel, TorchScript constants ...: an unknown model-named file is a G225
gap); prove a pickle safe (a clean read of the allow-list is "nothing found").
Best-effort (invariant I5): a clean result is not a proof.
"""

from __future__ import annotations

import ast
import json
import pickletools
import re
import struct
import zipfile
from pathlib import Path

from .model import Flag, Severity

HEAD = 16
_PICKLE_CAP = 64 * 1024 * 1024  # bytes read per pickle stream (ponytail: raise if real models hit it)
_READ_CAP = 16 * 1024 * 1024  # one read() inside a pickle (a 4 GB BINBYTES must not allocate)
_ST_HEADER_MAX = 100 * 1024 * 1024  # safetensors spec
_PY_CAP = 2 * 1024 * 1024
_ZIP_MEMBERS = 20000
_JSON_CAP = 8 * 1024 * 1024
_GGUF_CAP = 32 * 1024 * 1024
_PICKLE_SUFFIXES = {".pkl", ".pickle", ".joblib", ".pt", ".pth", ".ckpt", ".bin"}
_STRONG_SUFFIXES = _PICKLE_SUFFIXES - {".bin"}  # unparsable one of these = gap; a stray .bin is ignored
_COMPANION = re.compile(r"^(?:modeling|configuration|tokenization|processing|feature_extraction|image_processing)_.*\.py$", re.I)
_TRUST = re.compile(r"trust_remote_code\s*[=:]\s*[\"']?(?:true|True)\b")

_DANGEROUS_MODULES = (
    "os", "posix", "nt", "subprocess", "socket", "sys", "importlib", "shutil", "ctypes", "pty", "runpy",
    "urllib", "http", "requests", "pickle", "_pickle", "marshal", "base64", "commands", "popen2",
    "webbrowser", "code", "codeop", "multiprocessing", "asyncio", "threading", "tempfile", "ftplib",
    "smtplib", "telnetlib", "zipimport", "pkgutil", "pip", "operator", "types", "timeit", "cProfile",
    "profile", "pdb", "builtins_eval",
)
_DANGEROUS_BUILTINS = {
    "eval", "exec", "compile", "__import__", "open", "getattr", "setattr", "delattr", "globals",
    "locals", "vars", "input", "breakpoint", "execfile", "reload",
}
_ALLOWED = {
    ("collections", "OrderedDict"), ("torch._utils", None), ("torch", None),
    ("numpy.core.multiarray", "_reconstruct"), ("numpy.core.multiarray", "scalar"),
    ("numpy._core.multiarray", "_reconstruct"), ("numpy._core.multiarray", "scalar"),
    ("numpy", "dtype"), ("numpy", "ndarray"), ("torch.serialization", "_get_layout"),
}


def _allowed(mod: str, name: str) -> bool:
    if mod == "torch._utils":
        return name.startswith("_rebuild_")
    if mod == "torch":  # Storage types / dtypes / Size only
        return name.endswith(("Storage", "Size")) or name in {"float32", "float16", "bfloat16", "int64", "int32", "int8", "uint8", "bool", "float64"}
    return (mod, name) in _ALLOWED


def _dangerous(mod: str, name: str) -> bool:
    if mod in ("builtins", "__builtin__"):
        return name in _DANGEROUS_BUILTINS
    return any(mod == m or mod.startswith(m + ".") for m in _DANGEROUS_MODULES)


# --- format by first bytes ---------------------------------------------------
def _is_safetensors_head(head: bytes, size: int) -> bool:
    if len(head) < 9 or size < 9:
        return False
    n = struct.unpack("<Q", head[:8])[0]
    return 0 < n <= _ST_HEADER_MAX and 8 + n <= size and head[8:9] == b"{"


def detect(p: Path, head: bytes, size: int) -> str:
    """'zip' 'gguf' 'hdf5' 'safetensors' 'pickle' or '' (not a model format)."""
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return "zip"
    if head.startswith(b"GGUF"):
        return "gguf"
    if head.startswith(b"\x89HDF\r\n\x1a\n"):
        return "hdf5"
    if _is_safetensors_head(head, size):
        return "safetensors"
    if head[:1] == b"\x80" and len(head) > 1 and 2 <= head[1] <= 5:
        return "pickle"
    return ""


# --- pickle ------------------------------------------------------------------
class _Limit(Exception):
    pass


class _Capped:
    """File wrapper: no single read over _READ_CAP, no more than `cap` bytes in all.
    One byte can be pushed back (is another stream following?)."""

    def __init__(self, f, cap: int = _PICKLE_CAP):
        self.f, self.cap, self.used, self.buf = f, cap, 0, b""

    def _take(self, data: bytes) -> bytes:
        self.used += len(data)
        if self.used > self.cap:
            raise _Limit
        return data

    def read(self, n: int = -1) -> bytes:
        if n < 0 or n > _READ_CAP:
            raise _Limit
        head, self.buf = self.buf[:n], self.buf[n:]
        return self._take(head + self.f.read(n - len(head)))

    def readline(self, n: int = -1) -> bytes:
        n = _READ_CAP if n < 0 else min(n, _READ_CAP)
        if self.buf:
            head, self.buf = self.buf, b""
            return self._take(head if head == b"\n" else head + self.f.readline(n - 1))
        return self._take(self.f.readline(n))

    def more(self) -> bool:
        if not self.buf:
            self.buf = self.f.read(1)
        return bool(self.buf)

    def tell(self) -> int:
        return self.used


_STR_OPS = {"SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE", "STRING", "BINSTRING", "SHORT_BINSTRING"}
_NEUTRAL = {"PROTO", "FRAME", "MARK", "POP", "POP_MARK"}


def _scan_pickle(f) -> tuple[list[tuple[str, str]], int, str]:
    """Walk the opcodes of every pickle stream in `f` without running them.
    Returns (imports as (module, name), unresolved import count, end) where end is
    'ok' (last stream ended with STOP), 'broken' (ended inside a stream), 'limit'."""
    imports: list[tuple[str, str]] = []
    unresolved = 0
    f = _Capped(f)
    done = 0
    while True:
        recent: list = []  # last pushed values: str, or None for "something else"
        memo: dict[int, object] = {}
        stopped = False
        try:
            for op, arg, _pos in pickletools.genops(f):
                name = op.name
                if name in _STR_OPS:
                    recent.append(arg if isinstance(arg, str) else None)
                elif name == "MEMOIZE":
                    memo[len(memo)] = recent[-1] if recent else None
                elif name in ("PUT", "BINPUT", "LONG_BINPUT"):
                    memo[arg] = recent[-1] if recent else None
                elif name in ("GET", "BINGET", "LONG_BINGET"):
                    recent.append(memo.get(arg))
                elif name == "GLOBAL":
                    mod, _, nm = str(arg).partition(" ")
                    imports.append((mod, nm))
                    recent.append(None)
                elif name in ("INST",):
                    mod, _, nm = str(arg).partition(" ")
                    imports.append((mod, nm))
                    recent.append(None)
                elif name == "STACK_GLOBAL":
                    a = recent[-2:]
                    if len(a) == 2 and all(isinstance(x, str) for x in a):
                        imports.append((a[0], a[1]))
                    else:
                        unresolved += 1
                    recent.append(None)
                elif name in ("EXT1", "EXT2", "EXT4"):
                    unresolved += 1
                    recent.append(None)
                elif name == "STOP":
                    stopped = True
                elif name not in _NEUTRAL:
                    recent.append(None)
                del recent[:-8]  # only the tail matters
        except _Limit:
            return imports, unresolved, "limit"
        except Exception:  # genops: ValueError on a bad opcode or EOF inside a stream
            # garbage after a finished stream (legacy torch files end with raw tensor data) is not a break
            return imports, unresolved, "ok" if done else "broken"
        if not stopped:
            return imports, unresolved, "broken"
        done += 1
        try:
            if not f.more():
                return imports, unresolved, "ok"
        except Exception:
            return imports, unresolved, "ok"
        f.used = 0  # each stream gets its own cap


def _pickle_flags(rel: str, f, *, sure: bool) -> tuple[list[Flag], bool]:
    """(flags, was_pickle). `sure`: format already known from the first bytes."""
    imports, unresolved, end = _scan_pickle(f)
    if not sure and not imports and end != "ok":
        return [], False  # suffix said pickle, content does not parse as one
    flags: list[Flag] = []
    seen: set[tuple[str, str]] = set()
    for mod, nm in imports:
        if (mod, nm) in seen:
            continue
        seen.add((mod, nm))
        if _dangerous(mod, nm):
            flags.append(Flag(Severity.HIGH, "G222",
                              "pickle imports something that runs code or reaches the system",
                              evidence=f"{rel}: {mod}.{nm}"))
        elif not _allowed(mod, nm):
            flags.append(Flag(Severity.MEDIUM, "G223", "pickle imports outside the allow-list",
                              evidence=f"{rel}: {mod}.{nm}"))
    if end == "broken" and imports:
        flags.append(Flag(Severity.HIGH, "G224",
                          "pickle breaks off before STOP after importing (a loader runs the part before the break)",
                          evidence=f"{rel}: {len(imports)} import(s) before the break"))
    # whatever else was found, a pickle not read to its end leaves the gate unable to vouch: partial, exit 3
    if end == "broken":
        flags.append(Flag(Severity.LOW, "G225", "pickle could not be parsed to its end; the rest was not inspected",
                          evidence=rel))
    elif end == "limit":
        flags.append(Flag(Severity.LOW, "G225", "pickle over the analysis size limit; read only up to it",
                          evidence=rel))
    if unresolved:
        flags.append(Flag(Severity.LOW, "G225",
                          "pickle import that cannot be resolved without running it (STACK_GLOBAL / EXT)",
                          evidence=f"{rel}: {unresolved} import(s)"))
    return flags, True


def _zip_flags(p: Path, rel: str) -> tuple[list[Flag], bool, bool]:
    """(flags, has_pickle, is_keras)."""
    flags: list[Flag] = []
    has_pickle = keras = False
    try:
        zf = zipfile.ZipFile(p)
    except (zipfile.BadZipFile, OSError):
        return [Flag(Severity.LOW, "G225", "zip could not be opened; not inspected", evidence=rel)], False, False
    with zf:
        infos = zf.infolist()
        if len(infos) > _ZIP_MEMBERS:
            flags.append(Flag(Severity.LOW, "G225", f"zip with over {_ZIP_MEMBERS} members; only the first were inspected",
                              evidence=rel))
            infos = infos[:_ZIP_MEMBERS]
        names = {i.filename.lower() for i in infos}
        for info in infos:
            name = info.filename
            low = name.lower()
            if info.flag_bits & 0x1:
                flags.append(Flag(Severity.LOW, "G225", "encrypted zip member; not inspected",
                                  evidence=f"{rel}!{name}"))
            elif low.endswith((".pkl", ".pickle")) or _pickle_member(zf, info):
                has_pickle = True
                try:
                    with zf.open(info) as m:
                        fl, _ = _pickle_flags(f"{rel}!{name}", m, sure=True)
                    flags += fl
                except (OSError, RuntimeError, zipfile.BadZipFile, NotImplementedError):
                    flags.append(Flag(Severity.LOW, "G225", "zip member could not be read; not inspected",
                                      evidence=f"{rel}!{name}"))
            elif low == "config.json" and "metadata.json" in names:
                keras = True
                flags += _keras_config(zf, info, rel)
            elif _member_head(zf, info).startswith(b"PK\x03\x04"):
                flags.append(Flag(Severity.LOW, "G225", "zip inside a zip; not inspected", evidence=f"{rel}!{name}"))
    return flags, has_pickle, keras


def _member_head(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    if info.is_dir() or info.file_size == 0:
        return b""
    try:
        with zf.open(info) as m:
            return m.read(4)
    except (OSError, RuntimeError, zipfile.BadZipFile, NotImplementedError):
        return b""


def _pickle_member(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> bool:
    """A member that starts like a pickle (PROTO 2-5) is read as one whatever its name.
    ponytail: raw tensor members under `.../data/` are skipped (they start with arbitrary bytes)."""
    if "/data/" in "/" + info.filename.lower():
        return False
    h = _member_head(zf, info)
    return len(h) >= 2 and h[0] == 0x80 and 2 <= h[1] <= 5


def _keras_config(zf: zipfile.ZipFile, info: zipfile.ZipInfo, rel: str) -> list[Flag]:
    if info.file_size > _JSON_CAP:
        return [Flag(Severity.LOW, "G225", "keras config too large; not inspected", evidence=rel)]
    try:
        txt = zf.read(info).decode("utf-8", "replace")
    except (OSError, RuntimeError):
        return [Flag(Severity.LOW, "G225", "keras config could not be read", evidence=rel)]
    if re.search(r'"class_name"\s*:\s*"Lambda"|enable_unsafe_deserialization|__lambda__|"module"\s*:\s*"(?!keras|keras_hub|keras_nlp|builtins)', txt):
        return [Flag(Severity.MEDIUM, "G229", "Keras model holds a Lambda layer or custom code reference",
                     evidence=f"{rel}: config.json")]
    return []


# --- safetensors -------------------------------------------------------------
_DTYPE = {"F64": 8, "F32": 4, "F16": 2, "BF16": 2, "I64": 8, "I32": 4, "I16": 2, "I8": 1, "U64": 8, "U32": 4,
          "U16": 2, "U8": 1, "BOOL": 1, "F8_E4M3": 1, "F8_E5M2": 1, "F8_E8M0": 1, "C64": 8}


def _dup_free(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"duplicate key {k}")
        d[k] = v
    return d


def _safetensors_problem(p: Path, size: int) -> str | None:
    """None when the file keeps the safetensors format, else what is wrong."""
    try:
        with p.open("rb") as f:
            head = f.read(8)
            if len(head) < 8:
                return "shorter than 8 bytes"
            n = struct.unpack("<Q", head)[0]
            if n == 0 or n > _ST_HEADER_MAX:
                return f"header length {n} out of range"
            if 8 + n > size:
                return "header longer than the file"
            raw = f.read(n)
    except OSError:
        return "unreadable"
    if raw[:1] != b"{":
        return "header does not start with {"
    try:
        hdr = json.loads(raw.decode("utf-8"), object_pairs_hook=_dup_free)
    except (ValueError, RecursionError) as e:
        return f"header JSON invalid ({str(e)[:40]})"
    if not isinstance(hdr, dict):
        return "header is not an object"
    meta = hdr.pop("__metadata__", {})
    if not isinstance(meta, dict) or not all(isinstance(v, str) for v in meta.values()):
        return "__metadata__ holds a non-string"
    spans = []
    for k, t in hdr.items():
        if not isinstance(t, dict) or not isinstance(t.get("dtype"), str):
            return f"tensor {k!r} malformed"
        sh, off = t.get("shape"), t.get("data_offsets")
        if not (isinstance(sh, list) and all(type(x) is int and x >= 0 for x in sh)):
            return f"tensor {k!r} bad shape"
        if not (isinstance(off, list) and len(off) == 2 and all(type(x) is int and x >= 0 for x in off) and off[0] <= off[1]):
            return f"tensor {k!r} bad data_offsets"
        item = _DTYPE.get(t["dtype"])
        if item is not None:
            cnt = 1
            for x in sh:
                cnt *= x
            if cnt * item != off[1] - off[0]:
                return f"tensor {k!r} size does not match dtype x shape"
        spans.append((off[0], off[1]))
    pos = 0
    for b, e in sorted(spans):
        if b != pos:
            return "hole or overlap in data"
        pos = e
    if pos != size - 8 - n:
        return "data does not end where the file ends"
    return None


# --- GGUF --------------------------------------------------------------------
_GGUF_SCALAR = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}
_JINJA_INTERNALS = re.compile(r"__class__|__globals__|__subclasses__|__mro__|__builtins__|__import__|"
                              r"\bos\s*\.|popen|\bimport\b|lipsum\.|cycler\.|joiner\.|namespace\.__")


def _gguf_template(p: Path) -> tuple[str | None, bool]:
    """(chat template or None, parsed ok). Reads the key-value table only."""
    try:
        with p.open("rb") as f:
            data = f.read(_GGUF_CAP)
    except OSError:
        return None, False
    pos = 4
    try:
        _ver, _nt, nkv = struct.unpack_from("<IQQ", data, pos)
        pos += 20
        if nkv > 100000:
            return None, False

        def rd_str(o):
            (ln,) = struct.unpack_from("<Q", data, o)
            if ln > len(data):
                raise ValueError
            return data[o + 8:o + 8 + ln].decode("utf-8", "replace"), o + 8 + ln

        def skip(t, o):
            if t in _GGUF_SCALAR:
                return o + _GGUF_SCALAR[t]
            if t == 8:
                return rd_str(o)[1]
            if t == 9:
                (et, cnt) = struct.unpack_from("<IQ", data, o)
                o += 12
                for _ in range(cnt):
                    o = skip(et, o)
                    if o > len(data):
                        raise ValueError
                return o
            raise ValueError

        for _ in range(nkv):
            key, pos = rd_str(pos)
            (t,) = struct.unpack_from("<I", data, pos)
            pos += 4
            if t == 8 and key == "tokenizer.chat_template":
                return rd_str(pos)[0], True
            pos = skip(t, pos)
            if pos > len(data):
                return None, False
    except (struct.error, ValueError, RecursionError):
        return None, False
    return None, True


# --- companion python / config ----------------------------------------------
_RUN = {"eval", "exec", "compile", "__import__", "system", "popen", "Popen", "run", "call", "check_output",
        "check_call", "execv", "execve", "spawn", "urlopen", "get", "post", "create_connection", "connect"}
_RUN_MODS = {"os", "subprocess", "socket", "requests", "urllib", "httpx", "http", "ctypes", "pty", "runpy", "importlib"}
_SOFT = re.compile(r"os\.environ|getenv|\.ssh|\.aws|\.env\b|\.netrc|id_rsa|b64decode|marshal\.loads|codecs\.decode")


def _root_name(n: ast.AST) -> str:
    while isinstance(n, ast.Attribute):
        n = n.value
    return n.id if isinstance(n, ast.Name) else ""


class _ImportTime(ast.NodeVisitor):
    def __init__(self):
        self.hard: list[tuple[int, str]] = []
        self.soft: list[tuple[int, str]] = []

    def _fn(self, node):  # body runs later; decorators and defaults run now
        for d in node.decorator_list:
            self.visit(d)
        for d in node.args.defaults + [k for k in node.args.kw_defaults if k]:
            self.visit(d)

    visit_FunctionDef = visit_AsyncFunctionDef = _fn

    def visit_Lambda(self, node):
        for d in node.args.defaults:
            self.visit(d)

    def visit_Call(self, node):
        f = node.func
        nm = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""
        if nm in {"eval", "exec", "compile", "__import__"} or (nm in _RUN and _root_name(f) in _RUN_MODS):
            self.hard.append((node.lineno, nm))
        self.generic_visit(node)

    def visit_Attribute(self, node):
        s = f"{_root_name(node)}.{node.attr}"
        if _SOFT.search(s):
            self.soft.append((node.lineno, s))
        self.generic_visit(node)

    def visit_Constant(self, node):
        if isinstance(node.value, str) and len(node.value) < 200 and _SOFT.search(node.value):
            self.soft.append((node.lineno, node.value[:40]))


def _py_flags(p: Path, rel: str) -> list[Flag]:
    try:
        if p.stat().st_size > _PY_CAP:
            return [Flag(Severity.LOW, "G225", "companion .py too large; not inspected", evidence=rel)]
        tree = ast.parse(p.read_bytes().replace(b"\0", b""))
    except (SyntaxError, ValueError, RecursionError, MemoryError, OSError):
        return [Flag(Severity.LOW, "G225", "companion .py could not be parsed; not inspected", evidence=rel)]
    v = _ImportTime()
    v.visit(tree)
    out = []
    if v.hard:
        ln, nm = v.hard[0]
        out.append(Flag(Severity.HIGH, "G228", "companion .py runs a command / network / eval call at import time",
                        evidence=f"{rel}:{ln}: {nm}()"))
    if v.soft:
        ln, nm = v.soft[0]
        out.append(Flag(Severity.MEDIUM, "G228", "companion .py reads environment / key files / decodes at import time",
                        evidence=f"{rel}:{ln}: {nm}"))
    return out


# --- tree --------------------------------------------------------------------
def scan_tree(root: Path, files: list[Path]) -> list[Flag]:
    root = Path(root)
    flags: list[Flag] = []
    pickles: list[str] = []
    has_model = False
    candidates_py: list[tuple[Path, str]] = []
    jsons: list[tuple[Path, str]] = []
    texts: list[tuple[Path, str]] = []
    for p in files:
        rel = str(p.relative_to(root))
        suf = p.suffix.lower()
        try:
            size = p.stat().st_size
            with p.open("rb") as f:
                head = f.read(HEAD)
        except OSError:
            continue  # the main pass already reports an unreadable file (G911)
        fmt = detect(p, head, size)
        if suf == ".py":
            candidates_py.append((p, rel))
        elif suf == ".json":
            jsons.append((p, rel))
        if suf in (".py", ".json", ".md", ".txt", ".yaml", ".yml"):
            texts.append((p, rel))
        if suf == ".safetensors" or fmt == "safetensors":
            has_model = True
            if suf != ".safetensors" or fmt != "safetensors":
                why = f"named {suf or 'none'} but holds {fmt or 'something else'}" if fmt != "safetensors" else "safetensors under another name"
                if fmt == "safetensors":  # a valid safetensors with another suffix is fine
                    why = ""
                if why:
                    flags.append(Flag(Severity.HIGH, "G226", f"safetensors name does not match the content ({why})", evidence=rel))
                    continue
            prob = _safetensors_problem(p, size)
            if prob:
                flags.append(Flag(Severity.HIGH, "G226", "safetensors file breaks the format", evidence=f"{rel}: {prob}"))
            continue
        if suf == ".gguf" and fmt != "gguf":
            has_model = True
            flags.append(Flag(Severity.HIGH, "G226", f"named .gguf but holds {fmt or 'something else'}", evidence=rel))
            continue
        if fmt == "gguf":
            has_model = True
            tpl, ok = _gguf_template(p)
            if not ok:
                flags.append(Flag(Severity.LOW, "G225", "GGUF metadata could not be parsed; not inspected", evidence=rel))
            elif tpl is not None:
                sev = Severity.HIGH if _JINJA_INTERNALS.search(tpl) else Severity.LOW
                flags.append(Flag(sev, "G229", "GGUF chat template (Jinja) present; shown, not run",
                                  evidence=f"{rel}: {' '.join(tpl.split())[:80]}"))
            continue
        if fmt == "hdf5":
            has_model = True
            flags.append(Flag(Severity.MEDIUM, "G229", "HDF5 (.h5) model: Keras can run code from it; a person decides",
                              evidence=rel))
            continue
        if fmt == "zip" and (suf in _PICKLE_SUFFIXES or suf in (".keras", ".pt2")):
            has_model = True
            fl, has_pickle, _k = _zip_flags(p, rel)
            flags += fl
            if has_pickle:
                pickles.append(rel)
            elif suf in _STRONG_SUFFIXES:
                flags.append(Flag(Severity.LOW, "G225", "model-named zip without a pickle member; format not recognised",
                                  evidence=rel))
            continue
        if fmt == "pickle" or suf in _PICKLE_SUFFIXES:
            try:
                with p.open("rb") as f:
                    fl, was = _pickle_flags(rel, f, sure=fmt == "pickle")
            except OSError:
                continue
            if was:
                has_model = True
                pickles.append(rel)
                flags += fl
            elif suf in _STRONG_SUFFIXES:
                has_model = True
                flags.append(Flag(Severity.LOW, "G225", "model-named file in an unknown format; not inspected", evidence=rel))
    if pickles:
        ev = ", ".join(pickles[:3]) + (f" (+{len(pickles) - 3} more)" if len(pickles) > 3 else "")
        flags.append(Flag(Severity.MEDIUM, "G221",
                          "pickle-based model: loading can run code and no scan is complete; a person must decide",
                          evidence=ev))
    # companion code and config
    auto_map: list[str] = []
    for p, rel in jsons:
        try:
            if p.stat().st_size > _JSON_CAP:
                continue
            doc = json.loads(p.read_bytes().replace(b"\0", b"").decode("utf-8", "replace"))
        except (ValueError, OSError, RecursionError):
            continue
        if isinstance(doc, dict) and "auto_map" in doc:
            auto_map.append(rel)
            flags.append(Flag(Severity.MEDIUM, "G227", "config names code to import when the model loads (auto_map)",
                              evidence=rel))
    if has_model or auto_map:
        for p, rel in candidates_py:
            if _COMPANION.match(p.name):
                flags.append(Flag(Severity.MEDIUM, "G227", "companion code loaded with the model (trust_remote_code)", evidence=rel))
                flags += _py_flags(p, rel)
        for p, rel in texts:
            try:
                if p.stat().st_size > _PY_CAP:
                    continue
                m = _TRUST.search(p.read_text(encoding="utf-8", errors="ignore"))
            except OSError:
                continue
            if m:
                flags.append(Flag(Severity.MEDIUM, "G227", "trust_remote_code=True (setting it False elsewhere does not clear this)",
                                  evidence=rel))
    seen: set[tuple[str, str, str]] = set()
    out = []
    for f in flags:
        k = (f.code, f.evidence, f.message)
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out
