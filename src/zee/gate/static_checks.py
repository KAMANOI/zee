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

import re
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
# Only G501 is matched against this view; the other patterns keep reading
# the raw text. Zero-width set is deliberately small (no blanket strip of
# every invisible code point).
_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿"))
_MD_EMPHASIS = re.compile(r"[*_~`]+")


def _g501_view(text: str) -> str:
    """NFKC (fullwidth -> ASCII), drop zero-width chars, drop Markdown
    emphasis markers, so `Ｉｇｎｏｒｅ`, `Ig​nore`, `**Ignore**` all
    read as `Ignore`."""
    text = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)
    return _MD_EMPHASIS.sub("", text)


# Context rules: a paraphrase only fires when two *different* cues share a
# paragraph — a single word never does. Cues:
#   A = earlier instructions declared void / to be ignored
#   B = this text claims priority over everything else
#   C = keep something hidden from the user / asker
#   D = replace the requested answer with something else
# Fires on A+B, A+D, C+D, A+C.
# ponytail: fixed phrase lists — a determined paraphrase still slips past;
# a semantic classifier is the upgrade path, not longer lists.
# Japanese negation right after the keyword: 無視しないで / 無効にしないで /
# 隠さず / 無視せず / 無効ではありません. 無効です still matches.
_JA_NEG = r"(?!(?:に|では?)?(?:し|さ)?(?:ない|ず|ません|せず|ありません))"
_CUES: dict[str, re.Pattern[str]] = {
    "A": re.compile(
        r"\b(?:earlier|prior|previous|preceding|original|above)\s+"
        r"(?:guidance|directives?|instructions?)\b[^.\n]{0,30}?"
        r"\b(?:obsolete|void|invalid|null|cancell?ed|superseded|no\s+longer)"
        r"|\b(?:ignore|disregard|forget|discard)\b[^.\n]{0,20}?"
        r"\b(?:earlier|prior|previous|preceding|above)\s+"
        r"(?:guidance|directives?|instructions?)\b"
        r"|(?:これまで|以前|前|先|上記|既存|元|最初)の(?:すべての|全ての)?"
        r"(?:指示|命令|指令|プロンプト)[^。\n]{0,15}?"
        r"(?:無効|無視|破棄|忘れ|取り消)" + _JA_NEG,
        re.I,
    ),
    "B": re.compile(
        r"\b(?:takes?|has|gets?)\s+(?:priority|precedence)\s+over\b"
        r"|\bhighest\s+priority\b|\boverrides?\s+(?:all|any|every)\b"
        r"|最優先|何よりも優先",
        re.I,
    ),
    "C": re.compile(
        r"\b(?:hidden|secret|conceal\w*|hide)\b[^.\n]{0,30}?\bfrom\s+"
        r"(?:the\s+)?(?:user|person|human|requester|asker|operator)"
        r"|(?:ユーザー|利用者|依頼者|質問者|相手)(?:に|には|へ|から)[^。\n]{0,15}?"
        r"(?:(?:秘密|内緒|伏せ|隠)" + _JA_NEG + r"|知らせ(?:ない|ず)|伝え(?:ない|ず)|言わ(?:ない|ず))"
        r"|秘匿" + _JA_NEG,
        re.I,
    ),
    "D": re.compile(
        r"\b(?:replace|substitute|swap)\b[^.\n]{0,30}?"
        r"\b(?:answer|response|reply|output)\b"
        r"|\binstead\s+of\s+(?:the\s+)?(?:requested|actual|real)\s+"
        r"(?:answer|response|reply)\b"
        r"|(?:回答|返答|答え|応答)の代わりに|(?:回答|返答|答え|応答)を[^。\n]{0,10}?"
        r"(?:置き換え|差し替え)",
        re.I,
    ),
}
_CUE_PAIRS = (("A", "B"), ("A", "D"), ("C", "D"), ("A", "C"))
# Quoted spans are examples, not instructions (「…」 is how Japanese docs
# cite an attack string).
_QUOTED = re.compile(r"「[^」\n]*」|『[^』\n]*』|“[^”\n]*”|\"[^\"\n]*\"")
_EN_NEG = re.compile(
    r"\b(?:do\s+not|don't|never|must\s+not|should\s+not|shouldn't)\s+"
    r"(?:\w+\s+){0,2}$",
    re.I,
)


def _cue_hit(cue: str, para: str) -> re.Match[str] | None:
    for m in _CUES[cue].finditer(para):
        if not _EN_NEG.search(para[max(0, m.start() - 40):m.start()]):
            return m
    return None


# A paragraph that talks *about* attacks (teaching material, threat docs)
# is capped at MEDIUM: still blocks promotion, but does not read as HIGH.
# Adding these words to a payload therefore only buys MEDIUM, never LOW.
_META = re.compile(
    r"prompt[\s-]+injection|\binjection\b|\battackers?\b|\bpayloads?\b|"
    r"\badversar|攻撃|注入|インジェクション",
    re.I,
)


def _g501_context(view: str) -> tuple[Severity, str] | None:
    """(severity, evidence) when a paragraph pairs two injection cues.
    Quoted cues never reach HIGH, but are not dropped either: wrapping a
    payload in quotes buys MEDIUM, never LOW."""
    hit = _g501_pairs(_QUOTED.sub(" ", view))
    if hit:
        return hit
    hit = _g501_pairs(view)
    return (Severity.MEDIUM, hit[1] + " (quoted)") if hit else None


def _g501_pairs(view: str) -> tuple[Severity, str] | None:
    found = None
    for para in re.split(r"\n\s*\n", view):
        hits = {c: _cue_hit(c, para) for c in _CUES}
        for a, b in _CUE_PAIRS:
            if hits[a] and hits[b]:
                ev = f"[{a}+{b}] {hits[a].group(0)} … {hits[b].group(0)}"
                if not _META.search(para):
                    return Severity.HIGH, ev
                found = found or (Severity.MEDIUM, ev + " (discusses attacks)")
    return found

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
            hit = (sev, f"(normalized) {m.group(0)}") if m else _g501_context(view)
            if hit:
                sev, ev = hit
                ev = ev if len(ev) <= 120 else ev[:117] + "…"
                flags.append(Flag(sev, "G501", msg, evidence=f"{rel}: {ev}"))
    return flags
