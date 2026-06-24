"""Fetch an artifact into a quarantine directory — copy only, never run.

MVP supports a local filesystem source (file or directory). Remote
sources (URL / git / registry) are a later phase; keeping MVP local
means no network and no execution at all. Symlinks are preserved (not
followed) so a malicious symlink cannot pull in host files during copy.
"""

from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path
from typing import Optional

from ..telemetry.events_log import default_log_dir


def quarantine_base() -> Path:
    return default_log_dir() / "gate" / "quarantine"


def sha256_tree(root: Path) -> str:
    """Stable content hash over a file or directory tree."""
    root = Path(root)
    h = hashlib.sha256()
    if root.is_file():
        h.update(root.read_bytes())
        return h.hexdigest()
    for p in sorted(root.rglob("*")):
        rel = str(p.relative_to(root)).encode("utf-8")
        # Hash symlinks by their target string (NOT followed — no host read)
        # so a Rug Pull that only swaps a symlink target is still detected
        # as drift. The type tag keeps a file and a symlink of the same
        # name/bytes distinct.
        if p.is_symlink():
            h.update(b"L\0")
            h.update(rel)
            h.update(b"\0")
            try:
                h.update(os.readlink(p).encode("utf-8"))
            except OSError:
                pass
        elif p.is_file():
            h.update(b"F\0")
            h.update(rel)
            h.update(b"\0")
            try:
                h.update(p.read_bytes())
            except OSError:
                pass
    return h.hexdigest()


def fetch_local(source: str | Path, base: Optional[Path] = None) -> Path:
    """Copy `source` into the quarantine and return the copied root.

    Idempotent: the destination is keyed by content hash, so re-fetching
    the same bytes reuses the existing quarantine copy. Nothing is
    executed; this is a plain copy.
    """
    src = Path(source).expanduser()
    if not src.exists():
        raise FileNotFoundError(f"source not found: {source}")
    base = Path(base) if base else quarantine_base()
    digest = sha256_tree(src)[:16]
    dest = base / f"{src.name}-{digest}"
    if dest.exists():
        return dest  # already quarantined (no exec, idempotent)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if src.is_dir():
        shutil.copytree(src, dest, symlinks=True)
    else:
        dest.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest / src.name)
    return dest
