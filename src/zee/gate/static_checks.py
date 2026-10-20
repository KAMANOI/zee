"""Static inspection of a *fetched but never executed* artifact tree.

Reads files as text/bytes and flags the agent-threat patterns from the
handover doc (Phase 1): dynamic code execution, network-piped-to-shell,
download-then-exec, obfuscated/encoded blobs, credential-path reads,
type/magic-byte mismatch, and prompt-injection text embedded in
metadata. stdlib only; no file is ever run.

Flag codes:
    G1xx  manifest / install hooks
    G2xx  dangerous code patterns
    G3xx  obfuscation / encoding
    G4xx  file-type / magic-byte mismatch
    G5xx  prompt injection in metadata
    G205-G211, G602  how an agent's tools / sandbox are configured
          (agent_config.py: unquoted shell interpolation, custom computer
          tool, schema mismatch, code-running allowlists, log-only network
          policy, passwordless sudo, passwordless VNC, secret-file reads)
    G212-G216  tampering plugin: rewrites another package, re-applies on
          every start, injects an unreadable prompt, patches other plugins,
          README addressed to an AI assistant (tampering.py)
    G221-G229  AI model files: pickle / safetensors / GGUF / Keras / companion
          code, judged by the first bytes (modelfiles.py)
    G217-G220  procedure documents / plugin definitions that change the
          host's AI setup: register an outside MCP server, write into an
          AI-tool config file, declare an outside connection, start a
          browser with its sandbox off (instructions.py)
    (G6xx denylist lives in denylist.py)
    G7xx  symlinks (G701 escapes the tree = HIGH, G702 in-tree = LOW)
    G91x  gaps: not inspected / unreadable (G910 too large, G911 unreadable;
          they make the inspection PARTIAL and do not add to the score)

Detection is best-effort pattern matching, not complete coverage
(invariant I5): obfuscation can evade it, and a later phase wires in
Semgrep + a sandboxed behavioural run to catch what static scanning
misses.
"""

from __future__ import annotations

import functools
import re
import sys
import unicodedata
from pathlib import Path

from . import agent_config, modelfiles, tampering, textfile
from .model import Flag, Severity

# Suffixes that must NOT contain a binary executable signature.
_EXPECT_TEXT = textfile.TEXT_SUFFIXES

_MAX_READ_BYTES = 2 * 1024 * 1024  # don't slurp giant blobs

# G203/G204 as plain regexes are quadratic: from every `curl` / `exec(` /
# `atob(` the engine rescans to the end of the line (`"curl " * n`: 80 KB
# took 3.9 s). _LinearSearch finds the same leftmost start in one pass —
# each candidate token is paired with the next separator, looked up once
# per segment — and then runs the original regex anchored at that start,
# so the match (and evidence) is identical to `full.search(text)`.


def _first_ok_token(text, tokens, sep: re.Pattern[str], ok) -> int | None:
    """Start of the first token whose next `sep` hit satisfies ok(pos).
    Tokens come in order and contain no separator, so consecutive tokens
    before the same separator share one lookup: linear overall."""
    seg_end, good = -1, False
    for t in tokens:
        if t.end() > seg_end:
            m = sep.search(text, t.end())
            seg_end = m.start() if m else len(text)
            good = ok(seg_end)
        if good:
            return t.start()
    return None


class _LinearSearch:
    def __init__(self, full: re.Pattern[str], find_start) -> None:
        self.full, self.find_start, self.pattern = full, find_start, full.pattern

    def search(self, text: str) -> re.Match[str] | None:
        start = self.find_start(text)
        return None if start is None else self.full.match(text, start)


_G203_TOK = re.compile(r"(curl|wget)\b", re.I)
_G203_SEP = re.compile(r"[|\n]")
_G203_TAIL = re.compile(r"\|\s*(bash|sh|zsh)\b", re.I)


def _g203_start(text: str) -> int | None:
    # `[^\n|]*` stops at the first | or newline, so a token matches iff
    # that separator is a | followed by a shell.
    return _first_ok_token(
        text, _G203_TOK.finditer(text), _G203_SEP,
        lambda q: q < len(text) and _G203_TAIL.match(text, q) is not None,
    )


_G203 = _LinearSearch(
    re.compile(r"(curl|wget)\b[^\n|]*\|\s*(bash|sh|zsh)\b", re.I), _g203_start
)

_G204_DEC = re.compile(r"(atob|b64decode|base64\.b64decode)\s*\(", re.I)
_G204_DEC_SEP = re.compile(r"[)\n]")
_G204_EXE = re.compile(r"(eval|exec)\s*\(\s*", re.I)
_G204_ATOB = re.compile(r"atob", re.I)
_G204_EXE_SEP = re.compile(r"\n|b64decode", re.I)


def _g204_start(text: str) -> int | None:
    # Alt 1: decode call whose `(` closes before the line ends.
    a = _first_ok_token(
        text, _G204_DEC.finditer(text), _G204_DEC_SEP,
        lambda q: q < len(text) and text[q] == ")",
    )
    # Alt 2: eval/exec( followed by atob, or by b64decode later on the line
    # (`.*b64decode`): the first "\n or b64decode" after it must be the latter.
    b = None
    seg_end, good = -1, False
    for t in _G204_EXE.finditer(text):
        if _G204_ATOB.match(text, t.end()):
            b = t.start()
            break
        if t.end() > seg_end:
            m = _G204_EXE_SEP.search(text, t.end())
            seg_end = m.start() if m else len(text)
            good = m is not None and m.group(0) != "\n"
        if good:
            b = t.start()
            break
    starts = [x for x in (a, b) if x is not None]
    return min(starts) if starts else None


_G204 = _LinearSearch(
    re.compile(
        r"(atob|b64decode|base64\.b64decode)\s*\([^\n)]*\)\s*\)?\s*"
        r"|(eval|exec)\s*\(\s*(atob|.*b64decode)",
        re.I,
    ),
    _g204_start,
)

# (code, severity, compiled regex or _LinearSearch, human message)
_PATTERNS: list[tuple[str, Severity, "re.Pattern[str] | _LinearSearch", str]] = [
    (
        "G201", Severity.HIGH,
        re.compile(r"\b(eval|exec)\s*\(|\bFunction\s*\(", re.I),
        "dynamic code execution (eval/exec/Function)",
    ),
    (
        "G202", Severity.MEDIUM,
        re.compile(
            r"\bos\.system\b|\bsubprocess\b|child_process|\bspawn\s*\(|"
            r"\b(popen|Popen)\s*\(",
        ),
        "spawns a subprocess / shell",
    ),
    (
        "G203", Severity.HIGH,
        _G203,
        "pipes a download straight into a shell (curl|bash)",
    ),
    (
        "G204", Severity.HIGH,
        _G204,
        "decodes then executes an encoded payload",
    ),
    (
        # MEDIUM, not HIGH: long base64 also appears legitimately
        # (lockfile integrity hashes, source maps, embedded fonts/images),
        # so a single hit should not by itself block promotion.
        "G301", Severity.MEDIUM,
        re.compile(r"[A-Za-z0-9+/]{512,}={0,2}"),
        "long base64 blob (possible packed payload)",
    ),
    (
        "G302", Severity.MEDIUM,
        re.compile(r"(?:\\x[0-9a-fA-F]{2}){40,}|0x[0-9a-fA-F]{200,}"),
        "long hex blob",
    ),
    (
        "G601", Severity.MEDIUM,
        re.compile(
            r"\.ssh\b|\.aws\b|\.npmrc\b|\.pypirc\b|"
            r"\.config/gcloud|\.config/gh\b|\.docker/config|\.kube/config|"
            r"\.env\b|Cookies\b|Keychain\b|id_rsa\b",
        ),
        "reads credential / secret store paths",
    ),
    (
        "G501", Severity.HIGH,
        re.compile(
            r"ignore\s+(all\s+)?previous\s+instructions|"
            r"disregard\s+(the\s+)?(above|previous)|"
            r"you\s+are\s+now\b|system\s+prompt|"
            r"do\s+not\s+tell\s+the\s+user|exfiltrat",
            re.I,
        ),
        "prompt-injection style instruction text",
    ),
]
_G501 = next(p for p in _PATTERNS if p[0] == "G501")

# --- G501 hardening: normalized view + context rules ----------------------
# Only G501 reads this view; every other pattern keeps reading raw text.
# Confidence tiers: a known phrase found in the view is HIGH (same as the
# raw rule); a paraphrase found by the context rules is an estimate, so it
# is always MEDIUM. No downgrade path uses quotes or words an attacker can
# add (those were bypasses), and every pattern here is bounded/linear.
_MD_EMPHASIS = re.compile(r"[*_~`]+")
_WS = re.compile(r"\s+")
# Invisible code points that are not Cf: CGJ, variation selectors, Hangul
# fillers, Khmer vowel inherents.
_EXTRA_INVISIBLE = (
    [0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x3164, 0xFFA0]
    + list(range(0xFE00, 0xFE10)) + list(range(0xE0100, 0xE01F0))
)
# Cyrillic / Greek letters that render like Latin ones.
_HOMOGLYPHS = dict(zip(
    map(ord, "аеорсхуіѕјԁһӏАВЕКМНОРСТХУІЅЈαοριντκΑΒΕΖΗΙΚΜΝΟΡΤΥΧ"),
    "aeopcxyisjdhlABEKMHOPCTXYISJaopivtkABEZHIKMNOPTYX",
    strict=True,
))


@functools.cache
def _view_table() -> dict[int, int | None]:
    table: dict[int, int | None] = dict.fromkeys(
        c for c in range(sys.maxunicode + 1)
        if unicodedata.category(chr(c)) == "Cf"
    )
    table.update(dict.fromkeys(_EXTRA_INVISIBLE))
    table.update(_HOMOGLYPHS)
    return table


@functools.cache
def _long_combining_run() -> re.Pattern[str]:
    """Runs of more than _MAX_COMBINING_RUN combining marks (nonzero
    canonical combining class)."""
    cps = [c for c in range(sys.maxunicode + 1) if unicodedata.combining(chr(c))]
    ranges, start, prev = [], cps[0], cps[0]
    for c in cps[1:] + [-1]:
        if c != prev + 1:
            ranges.append(f"{re.escape(chr(start))}-{re.escape(chr(prev))}")
            start = c
        prev = c
    return re.compile(f"[{''.join(ranges)}]{{{_MAX_COMBINING_RUN + 1},}}")


# A real script stacks a handful of marks per letter; 32 is far above that.
# Marks are capped, never removed (removing them would turn で into て and
# break the Japanese negation rules), and letters are never touched, so a
# known phrase survives. Every other pattern still reads the raw text.
_MAX_COMBINING_RUN = 32


class _NFKDChar(dict):
    """ord -> NFKD of that single char, filled on first sight. Used with
    str.translate, so decomposing a text is linear."""

    def __missing__(self, cp: int) -> str:
        out = self[cp] = unicodedata.normalize("NFKD", chr(cp))
        return out


_NFKD_CHAR = _NFKDChar()


def _bounded_nfkc(text: str) -> str:
    """NFKC with a linear-time guarantee. Plain NFKC sorts each run of
    combining marks, which is quadratic in the run length, and the run can
    be *created* by decomposition (U+0F73, half-width ﾞ) so a pre-check on
    the input misses it. Instead: decompose char by char (linear), cap
    every combining run of the decomposed text, then NFC (reorder +
    compose, linear now that runs are bounded). Per-char NFKD followed by
    NFC equals NFKC whenever no run was capped."""
    if text.isascii():
        return text  # ASCII is already NFKC and has no combining marks
    text = text.translate(_NFKD_CHAR)
    text = _long_combining_run().sub(
        lambda m: m.group(0)[:_MAX_COMBINING_RUN], text
    )
    return unicodedata.normalize("NFC", text)


def _g501_view(text: str) -> str:
    """NFKC (fullwidth -> ASCII), drop every Cf char (zero-width, soft
    hyphen, bidi marks, ZWJ) and the extra invisibles, fold Cyrillic/Greek
    look-alikes to Latin, drop Markdown emphasis, collapse whitespace.
    `Ｉｇｎｏｒｅ`, `Ig\\u00adnore`, `Ign\\u043ere`, `**Ignore**` all read
    `Ignore`."""
    text = _bounded_nfkc(text).translate(_view_table())
    return _WS.sub(" ", _MD_EMPHASIS.sub("", text))


# Context rules (MEDIUM): two *different* cues within _CUE_WINDOW chars of
# the collapsed view (blank lines do not reset it). A single cue never fires.
#   A = earlier instructions declared void / to be ignored
#   B = this text claims priority over everything else
#   C = keep *this instruction/replacement* hidden
#   D = replace the *requested* answer
# ponytail: fixed phrase lists — a determined paraphrase still slips past;
# a semantic classifier is the upgrade path, not longer lists.
_CUE_WINDOW = 400
# Japanese negation/prohibition right after the keyword: 無視しないで /
# 無効にしないで / 隠さず / 無視せず / 無効ではありません / 無視することは禁止.
_JA_NEG = (
    r"(?!(?:に|では?)?(?:し|さ)?(?:ない|ず|ません|せず|ありません)"
    r"|に?(?:する|すること|して|し)?(?:は|を)?(?:禁止|いけ|なら|だめ|ダメ))"
)
_JA_DOC = r"(?:指示|命令|指令|プロンプト)(?!書)"
_CUES: dict[str, re.Pattern[str]] = {
    "A": re.compile(
        r"\b(?:earlier|prior|previous|preceding|original|above) "
        r"(?:guidance|directives?|instructions?)\b[^.]{0,30}?"
        r"\b(?:obsolete|void|invalid|null|cancell?ed|superseded|no longer)"
        r"|\b(?:ignore|disregard|forget|discard)\b[^.]{0,20}?"
        r"\b(?:earlier|prior|previous|preceding|above) "
        r"(?:guidance|directives?|instructions?)\b"
        r"|(?:これまで|以前|前|先|上記|既存|元|最初)の(?:すべての|全ての)?"
        + _JA_DOC + r"[^。]{0,15}?(?:無効|無視|破棄|忘れ|取り消)" + _JA_NEG,
        re.I,
    ),
    "B": re.compile(
        r"\b(?:takes?|has|gets?) (?:priority|precedence) over\b"
        r"|\bhighest priority\b|\boverrides? (?:all|any|every)\b"
        r"|(?:最優先|何よりも優先)" + _JA_NEG,
        re.I,
    ),
    "C": re.compile(
        r"\b(?:this|these|the|that) (?:instructions?|directives?|"
        r"replacement|change|override)\b[^.]{0,30}?"
        r"\b(?:hidden|secret|concealed)\b"
        r"|\b(?:hide|conceal) (?:this|these|the|that) (?:instructions?|"
        r"directives?|replacement|change|override)\b"
        r"|(?:この|本|これらの)?(?:指示|命令|指令|置き換え|差し替え)(?!書)"
        r"[^。]{0,15}?(?:秘密|内緒|伏せ|隠|秘匿)" + _JA_NEG,
        re.I,
    ),
    "D": re.compile(
        r"\b(?:replace|substitute|swap) (?:the |your )?"
        r"(?:requested|actual|real|original|user'?s) (?:answer|response|reply)"
        r"|\binstead of (?:the )?(?:requested|actual|real) "
        r"(?:answer|response|reply)\b"
        r"|(?:依頼|質問|要求)された(?:回答|返答|答え|応答)の代わりに",
        re.I,
    ),
}
_CUE_PAIRS = (("A", "B"), ("A", "D"), ("C", "D"), ("A", "C"))
_EN_NEG = re.compile(
    r"(?:\b(?:do|does|did|will|would|should|must|can|is|are|was|were) not"
    r"|\b(?:don|doesn|didn|won|wouldn|shouldn|mustn|isn|aren|wasn|weren)'t"
    r"|\bcannot|\bnever) (?!(?:merely|only|just|simply)\b)(?:\w+ ){0,2}$",
    re.I,
)
# "not merely / only / just / simply" is emphasis, not negation, both
# inside the cue and right before it.
_EN_NEG_IN = re.compile(
    r"(?:\b(?:not|never)\b|n't\b)(?! (?:merely|only|just|simply)\b)", re.I
)  # "not merely obsolete" is emphasis, not negation


def _cue_hits(cue: str, view: str) -> list[re.Match[str]]:
    out = []
    for m in _CUES[cue].finditer(view):
        if _EN_NEG_IN.search(m.group(0)):
            continue  # "Earlier guidance is not obsolete"
        if _EN_NEG.search(view[max(0, m.start() - 40):m.start()]):
            continue  # "Do not treat earlier guidance as obsolete"
        out.append(m)  # no cap: a cap lets cue padding hide the real pair
    return out


def _g501_context(view: str) -> str | None:
    """Evidence when two different cues sit within _CUE_WINDOW chars."""
    hits = {c: _cue_hits(c, view) for c in "AC"}
    if not (hits["A"] or hits["C"]):
        return None  # every pair needs A or C; skip the B/D scans
    hits.update({c: _cue_hits(c, view) for c in "BD"})
    for a, b in _CUE_PAIRS:
        xs, ys, i, j = hits[a], hits[b], 0, 0  # both sorted by start: O(A+B)
        while i < len(xs) and j < len(ys):
            d = xs[i].start() - ys[j].start()
            if abs(d) <= _CUE_WINDOW:
                return f"[{a}+{b}] {xs[i].group(0)} … {ys[j].group(0)}"
            if d < 0:
                i += 1
            else:
                j += 1
    return None


# Binary executable signatures that must not appear in a text-typed file.
_MAGIC = [
    (b"\x7fELF", "ELF executable"),
    (b"MZ", "Windows PE executable"),
    (b"\xca\xfe\xba\xbe", "Mach-O fat binary"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit binary"),
    (b"\xfe\xed\xfa\xce", "Mach-O binary"),
]


def _iter_files(root: Path):
    for p in sorted(root.rglob("*")):
        if p.is_file() and not p.is_symlink():
            yield p


def _magic_flag(path: Path, head: bytes, rel: str) -> Flag | None:
    if path.suffix.lower() not in _EXPECT_TEXT:
        return None
    for sig, label in _MAGIC:
        if head.startswith(sig):
            return Flag(
                Severity.HIGH, "G401",
                f"file is typed as text but is a {label}",
                evidence=f"{rel} (magic {head[:4]!r})",
            )
    return None


def _symlink_flags(root: Path) -> list[Flag]:
    """A symlink that escapes the artifact tree can leak host files into
    the install dir on promotion, so flag it HIGH (in-tree links LOW)."""
    flags: list[Flag] = []
    root_resolved = str(root.resolve())
    for p in sorted(root.rglob("*")):
        if not p.is_symlink():
            continue
        rel = str(p.relative_to(root))
        try:
            target = str(p.resolve())
            inside = target == root_resolved or target.startswith(
                root_resolved + "/"
            )
        except OSError:
            inside = False
        try:
            link = str(p.readlink())
        except OSError:
            link = "?"
        if inside:
            flags.append(
                Flag(Severity.LOW, "G702", "symlink inside the artifact",
                     evidence=f"{rel} -> {link}")
            )
        else:
            flags.append(
                Flag(
                    Severity.HIGH, "G701",
                    "symlink escapes the artifact (possible host-file leak)",
                    evidence=f"{rel} -> {link}",
                )
            )
    return flags


def _unread(rel: str) -> Flag:
    return Flag(
        Severity.LOW, "G911",
        "file could not be read; its contents were not inspected",
        evidence=rel,
    )


def scan_tree(root: Path) -> list[Flag]:
    """Inspect every file under `root` without executing anything."""
    root = Path(root)
    flags: list[Flag] = _symlink_flags(root)
    seen: set[tuple[str, str]] = set()  # de-dup (code, file)
    for path in _iter_files(root):
        rel = str(path.relative_to(root))
        # Read only the first bytes for the magic check — never slurp the
        # whole (possibly multi-GB) file into memory.
        try:
            with path.open("rb") as f:
                sample = f.read(8192)
        except OSError:
            flags.append(_unread(rel))
            continue
        mf = _magic_flag(path, sample[:8], rel)
        if mf:
            flags.append(mf)
        # Text is judged by content as well as suffix: a .html, Makefile or
        # extensionless script with eval() must not pass as "nothing found".
        # One rule for every check (textfile.classify): a binary file is
        # outside the text scan; a text-typed file that looks binary is still
        # scanned (NUL removed) and reported here, once, as a gap.
        kind = textfile.classify(path, sample)
        if kind == textfile.BINARY:
            continue
        if kind == textfile.GAP:
            flags.append(Flag(
                Severity.LOW, "G911",
                "text-typed file contains NUL bytes (looks binary); it was read with "
                "them removed and the result may be incomplete",
                evidence=rel,
            ))
        try:
            if path.stat().st_size > _MAX_READ_BYTES:
                # Too large to scan as text (DoS guard). Not a clean pass:
                # the text patterns never ran on this file.
                flags.append(Flag(
                    Severity.LOW, "G910",
                    "text file too large to inspect; patterns not checked",
                    evidence=f"{rel} (over {_MAX_READ_BYTES} bytes)",
                ))
                continue
            text, _ = textfile.read(path)
        except (OSError, MemoryError):
            flags.append(_unread(rel))
            continue
        if text is None:  # changed to binary between the two reads
            flags.append(_unread(rel))
            continue
        for code, sev, pat, msg in _PATTERNS:
            m = pat.search(text)
            if not m:
                continue
            key = (code, rel)
            if key in seen:
                continue
            seen.add(key)
            snippet = m.group(0)
            snippet = snippet if len(snippet) <= 80 else snippet[:77] + "…"
            flags.append(
                Flag(sev, code, f"{msg}", evidence=f"{rel}: {snippet}")
            )
        if ("G501", rel) not in seen:
            _, sev, pat, msg = _G501
            view = _g501_view(text)
            m = pat.search(view)
            if m:
                ev = f"(normalized) {m.group(0)}"
            else:
                sev, ev = Severity.MEDIUM, _g501_context(view)
            if ev:
                ev = ev if len(ev) <= 120 else ev[:117] + "…"
                flags.append(Flag(sev, "G501", msg, evidence=f"{rel}: {ev}"))
    files = list(_iter_files(root))
    flags += agent_config.scan_tree(root, files)
    flags += tampering.scan_tree(root, files)
    flags += modelfiles.scan_tree(root, files)
    return flags
