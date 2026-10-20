"""The one rule for "is this file text?", shared by every static check
(static_checks main pass, agent_config G205-G211/G602, tampering G212-G216,
instructions G217-G220). Judged on the raw bytes of the first 8 KiB.

- No NUL byte there: text.
- A file chosen by its name (Dockerfile, Makefile, README, a dotfile such as
  .bashrc / .env) or a `#!` script: text, whatever it holds.
- A NUL in a file whose suffix any check reads as text (TEXT_SUFFIXES): read
  with the NUL bytes removed AND reported by the main pass as G911 ("looks
  binary"), so a NUL can neither switch the checks off nor pass silently.
- Anything else with a NUL (image, archive): binary, outside the text scan.
  There is no exception by file content: macOS .DS_Store / ._x files are dotfiles,
  so they are read as text (their bytes are attacker-written like any other).
"""

from __future__ import annotations

import re
from pathlib import Path

HEAD = 8192

# Every suffix any check reads as text: static_checks' text types, tampering's
# _CODE | _CONFIG | _DOC and agent_config's _PY | _JS | _SHELLISH (tests keep
# this a superset of each).
TEXT_SUFFIXES = frozenset({
    ".py", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx",
    ".sh", ".bash", ".zsh", ".ps1", ".rb", ".pl",
    ".json", ".toml", ".yaml", ".yml", ".cfg", ".ini",
    ".md", ".markdown", ".txt", ".rst", ".html", ".htm",
})

_NAMED_TEXT = re.compile(
    r"^(?:Dockerfile|Containerfile|Makefile|GNUmakefile|Procfile|README|LICENSE|\.)", re.I)

TEXT, GAP, BINARY = "text", "gap", "binary"


def classify(p: Path, head: bytes) -> str:
    """TEXT, GAP (text-typed but looks binary: scanned and reported G911) or BINARY."""
    if b"\0" not in head:
        return TEXT
    if _NAMED_TEXT.match(p.name) or head.startswith(b"#!"):
        return TEXT
    return GAP if p.suffix.lower() in TEXT_SUFFIXES else BINARY


def read(p: Path) -> tuple[str | None, bool]:
    """(text as every check sees it, had NUL bytes). Text is None for a binary
    file. NUL bytes are removed anywhere in the file (deleted, not spaced: tokens
    and indentation stay as written). Raises OSError / MemoryError."""
    raw = p.read_bytes()
    if classify(p, raw[:HEAD]) == BINARY:
        return None, True
    # same decoding as Path.read_text: utf-8, bad bytes dropped, universal newlines
    text = raw.decode("utf-8", errors="ignore").replace("\r\n", "\n").replace("\r", "\n")
    nul = "\0" in text
    return (text.replace("\0", "") if nul else text), nul
