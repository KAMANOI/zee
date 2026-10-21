"""Static checks for AI model files (open weights) before they are installed.

Nothing is loaded or executed: no pickle.load / torch.load, nothing unpacked
to disk. The format is read from the first bytes, not from the suffix, and
every file in the tree is checked whatever kind the artifact was given.

Flag codes:
    G221  MEDIUM  the tree holds a pickle-based model (.bin/.pt/.pth/.ckpt/.pkl/
                  .joblib, or any zip, by first bytes, with a pickle inside). One flag per tree.
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
    G225  GAP     could not be read and positively confirmed: unknown or
                  unparsable format, over a size / time limit, encrypted zip, a
                  zip member that would not decompress, an unresolvable import, a
                  trailing pickle stream that imported then broke, GGUF version
                  other than 2/3 or a GGUF tensor of a type we cannot size,
                  companion .py too deep to walk. Inspection is then partial
                  (exit 3): the gate cannot vouch for it. A region never passes
                  by default -- fail toward "unscanned", never toward "ok".
    G226  HIGH    a file that is, or is named, safetensors but breaks the format
                  (bad header, duplicate keys, holes / overlaps, size mismatch,
                  or a pickle / zip under a .safetensors name), or a GGUF whose
                  key-value / tensor table does not fit the file (tensors with no
                  data, offsets past the end, bad alignment, or more tensor bytes
                  than the file holds).
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
import io
import json
import lzma
import pickletools
import re
import struct
import zipfile
import zlib
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
    if "." in name:  # STACK_GLOBAL resolves dotted names by getattr: torch + "os.system" must not pass
        return False
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
_NEUTRAL = {"PROTO", "FRAME"}  # everything else, MARK / POP included, breaks the "two strings in a row" chain


def _scan_pickle(f) -> tuple[list[tuple[str, str]], int, str]:
    """Walk the opcodes of every pickle stream in `f` without running them.
    Returns (imports as (module, name), unresolved import count, end) where end is
    'ok' (last stream ended with STOP), 'broken' (ended inside a stream), 'limit'."""
    imports: list[tuple[str, str]] = []
    unresolved = 0
    f = _Capped(f)
    done = 0
    while True:
        n0, u0 = len(imports), unresolved  # imports / unresolved before this stream attempt
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
            # garbage after a finished stream (legacy torch files end with raw tensor data) is not a break.
            # But we have no verified tensor-data span here, so a failed trailing segment that imported
            # anything (GLOBAL / STACK_GLOBAL / EXT) is a cut-off stream: a loader runs the part before the
            # break, including a REDUCE on that import. PROTO is not required (a proto-0 GLOBAL starts with
            # 'c', not 0x80). A segment that imported nothing is raw bytes that failed to parse -> not a cut.
            cut = len(imports) > n0 or unresolved > u0
            return imports, unresolved, "ok" if done and not cut else "broken"
        if not stopped:
            return imports, unresolved, "broken"
        done += 1
        try:
            if not f.more():
                return imports, unresolved, "ok"
        except Exception:
            # could not read on to see whether another stream follows: do not vouch "ok" for what was
            # not read. 'limit' adds G225 (partial, exit 3) without fabricating a G224 for a stream that
            # did reach STOP.
            return imports, unresolved, "limit"
        f.used = 0  # each stream gets its own cap


def _pickle_flags(rel: str, f, *, sure: bool) -> tuple[list[Flag], bool]:
    """(flags, was_pickle). `sure`: format already known from the first bytes."""
    imports, unresolved, end = _scan_pickle(f)
    if not sure and not imports and not unresolved and end == "broken":
        return [], False  # not name-confirmed, no callable primitive, and genops failed to parse it:
        # raw bytes that merely started like a pickle. Only 'broken' drops -- a 'limit' hit means the stream
        # parsed cleanly up to the cap (it IS a pickle we did not finish, kept as G225), and an unresolved
        # GLOBAL / EXT that then broke off is a real code path a loader would run, so it is kept too.
    flags: list[Flag] = []
    seen: set[tuple[str, str]] = set()
    for mod, nm in imports:
        if (mod, nm) in seen:
            continue
        seen.add((mod, nm))
        if "." in nm or _dangerous(mod, nm):
            flags.append(Flag(Severity.HIGH, "G222",
                              "pickle imports something that runs code or reaches the system (or walks a dotted attribute path)",
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


# Every way reading one zip member can fail -- a corrupt/unsupported compressor (zlib / lzma / bz2->OSError),
# a CRC mismatch or structural fault (BadZipFile), an unsupported method (NotImplementedError) or a short
# stream (EOFError). All of them map to "could not read" -> G225, never to a silent "ok".
_MEMBER_ERRORS = (OSError, RuntimeError, zipfile.BadZipFile, NotImplementedError, EOFError, zlib.error, lzma.LZMAError)


def _read_member(zf: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int = _PICKLE_CAP) -> bytes | None:
    """Decompress a zip member into memory, bounded by `limit` (plus one read). Returns the bytes, or
    None when the member cannot be read or decompressed -- the single choke point where any decode
    failure, at header-read or body-read, becomes G225 (fail toward unscanned)."""
    try:
        with zf.open(info) as m:
            out, got = [], 0
            while got <= limit:
                chunk = m.read(_READ_CAP)  # a bomb decompresses lazily: at most _READ_CAP output per read
                if not chunk:
                    return b"".join(out)
                out.append(chunk)
                got += len(chunk)
            return b"".join(out)  # over the cap; the pickle scanner's own cap then marks it G225 'limit'
    except _MEMBER_ERRORS:
        return None


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
                data = _read_member(zf, info)
                if data is None:
                    has_pickle = True
                    flags.append(Flag(Severity.LOW, "G225", "zip member could not be read; not inspected",
                                      evidence=f"{rel}!{name}"))
                else:  # a member only known as a pickle by its magic bytes is not 'sure': raw tensor bytes
                    # that happen to start with PROTO must not become a gap unless they parse as a real stream
                    fl, was = _pickle_flags(f"{rel}!{name}", io.BytesIO(data), sure=low.endswith((".pkl", ".pickle")))
                    has_pickle |= was
                    flags += fl
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
    except _MEMBER_ERRORS:
        return b""


def _pickle_member(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> bool:
    """A member that starts like a pickle (PROTO 2-5) is read as one whatever its name or path.
    Path is never the sole reason to skip a member: a raw-tensor slot (e.g. `.../data/N`) is not a
    *confirmed* tensor region -- it is read, and bytes that are not a real pickle flag nothing."""
    h = _member_head(zf, info)
    return len(h) >= 2 and h[0] == 0x80 and 2 <= h[1] <= 5


def _keras_config(zf: zipfile.ZipFile, info: zipfile.ZipInfo, rel: str) -> list[Flag]:
    if info.file_size > _JSON_CAP:
        return [Flag(Severity.LOW, "G225", "keras config too large; not inspected", evidence=rel)]
    data = _read_member(zf, info, limit=_JSON_CAP)
    if data is None:
        return [Flag(Severity.LOW, "G225", "keras config could not be read", evidence=rel)]
    txt = data.decode("utf-8", "replace")
    if re.search(r'"class_name"\s*:\s*"Lambda"|enable_unsafe_deserialization|__lambda__|"module"\s*:\s*"(?!(?:keras|keras_hub|keras_nlp|builtins)[."])', txt):
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
# ggml tensor type id -> (block size in elements, bytes per block). From llama.cpp
# gguf-py/gguf/constants.py GGML_QUANT_SIZES (fetched 2026-10-21). A type id not here cannot be sized,
# so its tensor is a gap (G225), never silently vouched. Deprecated ids (4, 5, 31-33, 36-38) are absent.
_GGML_QUANT_SIZE = {
    0: (1, 4), 1: (1, 2), 2: (32, 18), 3: (32, 20), 6: (32, 22), 7: (32, 24), 8: (32, 34), 9: (32, 36),
    10: (256, 84), 11: (256, 110), 12: (256, 144), 13: (256, 176), 14: (256, 210), 15: (256, 292),
    16: (256, 66), 17: (256, 74), 18: (256, 98), 19: (256, 50), 20: (32, 18), 21: (256, 110), 22: (256, 82),
    23: (256, 136), 24: (1, 1), 25: (1, 2), 26: (1, 4), 27: (1, 8), 28: (1, 8), 29: (256, 56), 30: (1, 2),
    34: (256, 54), 35: (256, 66), 39: (32, 17), 40: (64, 36), 41: (128, 18), 42: (64, 18),
}
_JINJA_INTERNALS = re.compile(r"__class__|__globals__|__subclasses__|__mro__|__builtins__|__import__|"
                              r"\bos\s*\.|popen|\bimport\b|lipsum\.|cycler\.|joiner\.|namespace\.__")


def _gguf_read(p: Path, size: int) -> tuple[str | None, str]:
    """(chat template or None, state): state 'ok', 'gap' (unsupported version / over the read cap /
    unreadable) or 'corrupt: why' (the header contradicts itself or the file size)."""
    try:
        with p.open("rb") as f:
            data = f.read(_GGUF_CAP)
    except OSError:
        return None, "gap"
    tpl = None
    try:
        ver, nt, nkv = struct.unpack_from("<IQQ", data, 4)
        if ver not in (2, 3):  # v1 has 32-bit counts; anything else is unknown
            return None, "gap"
        pos = 24
        if nkv > 100000 or pos + nkv * 12 > size:
            return None, "corrupt: key-value count beyond the file"
        if pos + nt * 24 > size:  # each tensor entry is at least 24 bytes
            return None, f"corrupt: {nt} tensors declared, file too short"

        def rd_str(o):
            (ln,) = struct.unpack_from("<Q", data, o)
            if o + 8 + ln > len(data):
                raise struct.error
            return data[o + 8:o + 8 + ln].decode("utf-8", "replace"), o + 8 + ln

        def skip(t, o):
            if t in _GGUF_SCALAR:
                return o + _GGUF_SCALAR[t]
            if t == 8:
                return rd_str(o)[1]
            if t == 9:
                (et, cnt) = struct.unpack_from("<IQ", data, o)
                o += 12
                if o + cnt > size:  # every element takes at least one byte
                    raise ValueError
                for _ in range(cnt):
                    o = skip(et, o)
                    if o > len(data):
                        raise struct.error
                return o
            raise ValueError

        align = 32  # GGUF default; general.alignment (UINT32) overrides it
        for _ in range(nkv):
            key, pos = rd_str(pos)
            (t,) = struct.unpack_from("<I", data, pos)
            pos += 4
            if t == 8 and key == "tokenizer.chat_template":
                tpl = rd_str(pos)[0]
            elif t == 4 and key == "general.alignment":
                (align,) = struct.unpack_from("<I", data, pos)
            pos = skip(t, pos)
            if pos > len(data):
                raise struct.error
        if align <= 0 or align & (align - 1):  # the spec requires a power of two
            return tpl, f"corrupt: alignment {align} is not a power of two"
        unsized = False  # a tensor whose type we cannot size: the data region is then unverifiable (gap)
        max_end = 0  # furthest tensor end, measured from the start of the data section
        for i in range(nt):
            _name, pos = rd_str(pos)
            (nd,) = struct.unpack_from("<I", data, pos)
            if nd > 4:
                return tpl, f"corrupt: tensor {i} has {nd} dimensions"
            dims = struct.unpack_from(f"<{nd}Q", data, pos + 4)
            pos += 4 + 8 * nd
            typ, off = struct.unpack_from("<IQ", data, pos)
            pos += 12
            if pos + off > size:  # the offset alone already lands past the end of the file
                return tpl, f"corrupt: tensor {i} data offset beyond the file"
            qs = _GGML_QUANT_SIZE.get(typ)
            if qs is None:
                unsized = True
                continue
            block, tsize = qs
            cnt = 1
            for x in dims:
                cnt *= x
            nbytes = (cnt + block - 1) // block * tsize  # ceil over the block: never underestimate the need
            max_end = max(max_end, off + nbytes)
        if nt:
            data_start = (pos + align - 1) // align * align  # tensor data starts aligned after the table
            if data_start + max_end > size:  # the declared tensor bytes do not fit in the file
                return tpl, "corrupt: tensor data runs past the end of the file"
            if unsized:  # could not size every tensor -> cannot vouch for the whole data region
                return tpl, "gap"
            if pos >= size:
                return tpl, "corrupt: tensors declared but no data"
    except ValueError:
        return tpl, "corrupt: malformed key-value table (unknown type or count beyond the file)"
    except (struct.error, RecursionError):
        # ran off the bytes read: the file is shorter than its header says, or longer than the cap
        return tpl, "gap" if len(data) < size else "corrupt: header runs past the end of the file"
    return tpl, "ok"


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
        self.mod_alias: dict[str, str] = {}  # `import os as o` -> o: os
        self.name_alias: dict[str, tuple[str, str]] = {}  # `from os import system as s` -> s: (os, system)

    def visit_Import(self, node):
        for a in node.names:
            self.mod_alias[a.asname or a.name.split(".")[0]] = a.name.split(".")[0]

    def visit_ImportFrom(self, node):
        for a in node.names:
            self.name_alias[a.asname or a.name] = ((node.module or "").split(".")[0], a.name)

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
        root = self.mod_alias.get(_root_name(f), _root_name(f))
        if isinstance(f, ast.Name) and f.id in self.name_alias:
            root, nm = self.name_alias[f.id]
        if nm in {"eval", "exec", "compile", "__import__"} or (nm in _RUN and root in _RUN_MODS):
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
    out = []
    try:
        v.visit(tree)
    except (RecursionError, MemoryError):  # e.g. a long `1+1+...` chain: what was seen so far still counts
        out.append(Flag(Severity.LOW, "G225", "companion .py nested too deep to analyse; not fully inspected", evidence=rel))
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
        if fmt == "safetensors" and suf in _PICKLE_SUFFIXES:
            has_model = True  # a pickle-named file (torch.load reads it as a pickle) that starts like safetensors
            flags.append(Flag(Severity.HIGH, "G226", "named as a pickle model but starts like safetensors (name and content differ)", evidence=rel))
            with p.open("rb") as f:
                fl, _ = _pickle_flags(rel, f, sure=False)
            flags += fl
            continue
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
            tpl, state = _gguf_read(p, size)
            if state == "gap":
                flags.append(Flag(Severity.LOW, "G225", "GGUF metadata could not be read (version / size limit); not inspected", evidence=rel))
            elif state != "ok":
                flags.append(Flag(Severity.HIGH, "G226", "GGUF file breaks the format", evidence=f"{rel}: {state[9:]}"))
            if tpl is not None:
                sev = Severity.HIGH if _JINJA_INTERNALS.search(tpl) else Severity.LOW
                flags.append(Flag(sev, "G229", "GGUF chat template (Jinja) present; shown, not run",
                                  evidence=f"{rel}: {' '.join(tpl.split())[:80]}"))
            continue
        if fmt == "hdf5":
            has_model = True
            flags.append(Flag(Severity.MEDIUM, "G229", "HDF5 (.h5) model: Keras can run code from it; a person decides",
                              evidence=rel))
            continue
        if fmt == "zip":  # by first bytes: a pickle zip renamed weights.dat is still read
            named = suf in _PICKLE_SUFFIXES or suf in (".keras", ".pt2")
            fl, has_pickle, keras = _zip_flags(p, rel)
            if not (named or has_pickle or keras):
                continue  # ponytail: an ordinary zip (.docx/.whl) without a pickle: its nested / encrypted members are not gaps
            has_model = True
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
    targets: set[str] = set()
    for p, rel in jsons:
        try:
            if p.stat().st_size > _JSON_CAP:
                continue
            doc = json.loads(p.read_bytes().replace(b"\0", b"").decode("utf-8", "replace"))
        except (ValueError, OSError, RecursionError):
            continue
        if isinstance(doc, dict) and "auto_map" in doc:
            auto_map.append(rel)
            stack = [doc["auto_map"]]
            while stack:  # {"AutoModel": "modeling_x.X"} / lists / "repo--modeling_x.X"
                v = stack.pop()
                if isinstance(v, str):
                    targets.add(v.rsplit("--", 1)[-1].split(".")[0])
                elif isinstance(v, dict):
                    stack += list(v.values())
                elif isinstance(v, list):
                    stack += v
            flags.append(Flag(Severity.MEDIUM, "G227", "config names code to import when the model loads (auto_map)",
                              evidence=rel))
    if has_model or auto_map:
        for p, rel in candidates_py:
            if _COMPANION.match(p.name) or p.stem in targets:
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
