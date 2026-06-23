"""Local denylist check (hashes / names / domains).

The denylist ships in the repo (``denylist.json``) and is refreshed from
GitHub — no server, no central service (invariants I1/I4). A match is a
high-severity flag.
"""

from __future__ import annotations

import json
from pathlib import Path

from .model import Artifact, Flag, Severity

_DATA = Path(__file__).with_name("denylist.json")


def _load() -> dict:
    try:
        data = json.loads(_DATA.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"hashes": [], "names": [], "domains": []}
    return data if isinstance(data, dict) else {}


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
