"""Local denylist check (hashes / names / domains).

Two sources, merged: the repo-shipped ``denylist.json`` (refreshed from
GitHub — no server, no central service; invariants I1/I4) and a local
overlay in the state dir that this machine grows itself. Phase 3 writes a
Rug-Pulled artifact's new hash into the overlay, so once the gate has
seen an artifact turn malicious, re-installing that exact version is
blocked everywhere the overlay is consulted — input and output sharing
the same threat record. A match on either source is a high-severity flag.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..telemetry.events_log import default_log_dir
from .model import Artifact, Flag, Severity

_DATA = Path(__file__).with_name("denylist.json")


def local_denylist_path() -> Path:
    """Machine-local denylist overlay (state dir, owner-only)."""
    return default_log_dir() / "gate" / "denylist_local.json"


def _load_one(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _load() -> dict:
    repo = _load_one(_DATA)
    local = _load_one(local_denylist_path())
    merged: dict[str, list] = {"hashes": [], "names": [], "domains": []}
    for src in (repo, local):
        for key in merged:
            vals = src.get(key, [])
            if isinstance(vals, list):
                merged[key].extend(str(v) for v in vals)
    # de-dup while preserving order
    for key in merged:
        merged[key] = list(dict.fromkeys(merged[key]))
    return merged


def add_local(*, hashes: tuple[str, ...] = (), names: tuple[str, ...] = ()) -> None:
    """Append hashes / names to the machine-local denylist overlay.

    Idempotent: an entry already present (in either source) is not
    re-added. Used by Phase 3 when an installed artifact drifts from its
    pinned hash (a confirmed Rug Pull).
    """
    path = local_denylist_path()
    current = _load_one(path)
    cur_hashes = list(current.get("hashes", []) if isinstance(current.get("hashes"), list) else [])
    cur_names = list(current.get("names", []) if isinstance(current.get("names"), list) else [])
    known = _load()  # repo + local, to avoid re-adding repo entries
    for h in hashes:
        if h and h not in cur_hashes and h not in set(known["hashes"]):
            cur_hashes.append(h)
    for n in names:
        if n and n not in cur_names and n not in set(known["names"]):
            cur_names.append(n)
    out = {
        "hashes": cur_hashes,
        "names": cur_names,
        "domains": current.get("domains", []),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except (OSError, NotImplementedError):
        pass
    existed = path.exists()
    path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    if not existed:
        try:
            os.chmod(path, 0o600)
        except (OSError, NotImplementedError):
            pass


def check(artifact: Artifact) -> list[Flag]:
    data = _load()
    flags: list[Flag] = []
    if artifact.content_hash in set(data.get("hashes", [])):
        flags.append(
            Flag(
                Severity.HIGH, "G610",
                "content hash is on the denylist",
                evidence=artifact.content_hash[:16],
            )
        )
    if artifact.name in set(data.get("names", [])):
        flags.append(
            Flag(
                Severity.HIGH, "G611",
                "name is on the denylist",
                evidence=artifact.name,
            )
        )
    return flags
