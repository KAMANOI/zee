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

import bisect
import functools
import re
import sys
import unicodedata
from pathlib import Path

from .model import Flag, Severity

# Files we will read as text for pattern scanning.
_TEXT_SUFFIXES = {
    ".py", ".js", ".ts", ".mjs", ".cjs", ".sh", ".bash", ".zsh",
    ".json", ".toml", ".yaml", ".yml", ".md", ".txt", ".cfg", ".ini",
    ".rb", ".pl", ".ps1",
}
# Suffixes that must NOT contain a binary executable signature.
_EXPECT_TEXT = _TEXT_SUFFIXES

_MAX_READ_BYTES = 2 * 1024 * 1024  # don't slurp giant blobs

# (code, severity, compiled-regex, human message)
_PATTERNS: list[tuple[str, Severity, re.Pattern[str], str]] = [
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
        re.compile(r"(curl|wget)\b[^\n|]*\|\s*(bash|sh|zsh)\b", re.I),
        "pipes a download straight into a shell (curl|bash)",
    ),
    (
        "G204", Severity.HIGH,
        re.compile(
            r"(atob|b64decode|base64\.b64decode)\s*\([^\n)]*\)\s*\)?\s*"
            r"|(eval|exec)\s*\(\s*(atob|.*b64decode)",
            re.I,
        ),
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


def _g501_view(text: str) -> str:
    """NFKC (fullwidth -> ASCII), drop every Cf char (zero-width, soft
    hyphen, bidi marks, ZWJ) and the extra invisibles, fold Cyrillic/Greek
    look-alikes to Latin, drop Markdown emphasis, collapse whitespace.
    `Ｉｇｎｏｒｅ`, `Ig\\u00adnore`, `Ign\\u043ere`, `**Ignore**` all read
    `Ignore`."""
    text = unicodedata.normalize("NFKC", text).translate(_view_table())
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
        r"|最優先|何よりも優先",
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
    r"\b(?:do not|don't|never|must not|should not|shouldn't) (?:\w+ ){0,2}$",
    re.I,
)
_EN_NEG_IN = re.compile(r"\b(?:not|never)\b|n't\b", re.I)


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
        starts = [m.start() for m in hits[b]]
        for ma in hits[a]:
            i = bisect.bisect_left(starts, ma.start() - _CUE_WINDOW)
            if i < len(starts) and starts[i] <= ma.start() + _CUE_WINDOW:
                mb = hits[b][i]
                return f"[{a}+{b}] {ma.group(0)} … {mb.group(0)}"
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
        # NUL bytes mean binary (image, archive), which is outside the text scan.
        if path.suffix.lower() not in _TEXT_SUFFIXES and b"\0" in sample:
            continue
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
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
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
    return flags
