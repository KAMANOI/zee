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

Detection is best-effort pattern matching, not complete coverage
(invariant I5): obfuscation can evade it, and a later phase wires in
Semgrep + a sandboxed behavioural run to catch what static scanning
misses.
"""

from __future__ import annotations

import re
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
                head = f.read(8)
        except OSError:
            continue
        mf = _magic_flag(path, head, rel)
        if mf:
            flags.append(mf)
        if path.suffix.lower() not in _TEXT_SUFFIXES:
            continue
        try:
            if path.stat().st_size > _MAX_READ_BYTES:
                continue  # too large to scan as text; skip (DoS guard)
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
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
    return flags
