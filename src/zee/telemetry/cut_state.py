"""Cut-state log (spec L2, v0.3).

When Zee cuts the network, it records exactly which interfaces /
services / firewall-rules it modified. Recovery (``zee restore``)
reads that record and only undoes Zee's own changes, so an interface
disabled by another tool at the same time is no longer re-enabled as
a side effect (the v0.2 ``restore`` behaviour).

The log is JSON Lines under the same state directory as
``events.jsonl`` and ``metrics.jsonl`` (parent 0700, file 0600). Each
``cut`` record has a matching ``resolved`` record once ``zee restore``
completes; ``latest_unresolved_for(asset_id)`` walks the log and
returns the most recent unresolved cut, or None.

When the log is missing, damaged, or has no unresolved record for an
asset_id, the recovery layer refuses the normal restore (Z605); only the
explicit ``--all-interfaces`` emergency restore re-enables everything.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .events_log import default_log_dir

logger = logging.getLogger(__name__)


def default_cut_state_path() -> Path:
    return default_log_dir() / "cut_state.jsonl"


# Recorded for a Linux full cut done with `nmcli networking off` (not an
# interface name; Linux interface names are at most 15 characters).
SENTINEL_LINUX_NMCLI = "__zee_nmcli_networking__"
# iptables egress cut and the kernel backend its `iptables` used.
SENTINEL_LINUX_IPTABLES_EGRESS = "__zee_iptables_egress_chain__"
IPT_BACKEND_PREFIX = "__zee_iptables_backend__:"


@dataclass(frozen=True)
class CutRecord:
    asset_id: str
    cut_at: datetime
    method: str  # "full" / "egress"
    platform: str  # "linux" / "darwin" / "win32"
    modified: tuple[str, ...]
    # (kind, name) per changed thing, kind = "firewall" | "nmcli" | "iface".
    # The kind comes from the cut method of the line that recorded it, never
    # from the name (a real service may be named like a Zee rule).
    pairs: tuple[tuple[str, str], ...] = ()

    def entries(self) -> tuple[tuple[str, str], ...]:
        return self.pairs or tuple(_kind(self.method, self.platform, m) for m in self.modified)


def _kind(method: str, platform: str, name: str) -> tuple[str, str]:
    if method == "egress":
        return ("firewall", name)
    if platform.startswith("linux") and name == SENTINEL_LINUX_NMCLI:
        return ("nmcli", name)
    return ("iface", name)


_PLATFORMS = ("linux", "darwin", "win32")


def _parse(raw: object) -> "CutRecord | str":
    """Validate one ledger line. Returns a CutRecord for ``cut``, the asset_id
    (str) for ``resolved``; raises ValueError/KeyError/TypeError otherwise."""
    if not isinstance(raw, dict):
        raise TypeError("record must be an object")
    asset_id = raw["asset_id"]
    if not isinstance(asset_id, str) or not asset_id:
        raise ValueError("asset_id must be a non-empty string")
    if raw.get("type") == "resolved":
        if datetime.fromisoformat(raw["resolved_at"]).tzinfo is None:
            raise ValueError("resolved_at must include timezone")
        return asset_id
    if raw.get("type") != "cut":
        raise ValueError("unknown record type")
    cut_at = datetime.fromisoformat(raw["cut_at"])
    if raw["method"] not in ("full", "egress"):
        raise ValueError("invalid method")
    platform = raw["platform"]
    if not isinstance(platform, str) or not platform.startswith(_PLATFORMS):
        raise ValueError("invalid platform")
    modified = raw["modified"]
    if not isinstance(modified, list) or not modified or \
            not all(isinstance(m, str) and m for m in modified):
        raise ValueError("modified must be a non-empty list of names")
    if SENTINEL_LINUX_IPTABLES_EGRESS in modified and not any(
            m.startswith(IPT_BACKEND_PREFIX) for m in modified):
        # Per record, before records are merged: an iptables cut that did not
        # say its backend (before v0.13.0) stays "unknown" even when a later
        # cut of the same asset names one, so restore checks both.
        modified = [*modified, IPT_BACKEND_PREFIX + "unknown"]
    return CutRecord(asset_id=asset_id, cut_at=cut_at, method=raw["method"],
                     platform=platform, modified=tuple(modified))


class CutStateLog:
    """Append-only JSON Lines log of ``cut`` and ``resolved`` events."""

    def __init__(self, path: Optional[Path] = None) -> None:
        # No filesystem side effects here: readers (`zee status`, the
        # read-only MCP layer) construct this too. The directory is
        # created / tightened only when a record is actually written.
        self.path = path or default_cut_state_path()

    def record_cut(
        self,
        *,
        asset_id: str,
        method: str,
        platform: str,
        modified: list[str],
        verified: Optional[str] = None,
    ) -> None:
        rec = {
            "type": "cut",
            "asset_id": asset_id,
            "cut_at": datetime.now(timezone.utc).isoformat(),
            "method": method,
            "platform": platform,
            "modified": list(modified),
        }
        if verified is not None:  # read-back after the cut: confirmed / missing / unverified
            rec["verified"] = verified
        self._append(rec)

    def mark_resolved(self, asset_id: str) -> None:
        rec = {
            "type": "resolved",
            "asset_id": asset_id,
            "resolved_at": datetime.now(timezone.utc).isoformat(),
        }
        self._append(rec)

    def latest_unresolved_for(self, asset_id: str) -> Optional[CutRecord]:
        """Return the unresolved cut for ``asset_id`` (see ``unresolved_for``)."""
        return self.unresolved_for(asset_id)[0]

    def unresolved_for(self, asset_id: str) -> tuple[Optional[CutRecord], bool]:
        """Return (unresolved cut for ``asset_id`` or None, ledger_damaged).

        Walks the log in order. ``cut`` records since the last ``resolved``
        for the asset are merged: ``modified`` is the ordered union, so a
        second (e.g. partial) cut does not hide what the first one changed;
        ``cut_at`` / ``method`` / ``platform`` come from the latest cut.

        ``ledger_damaged`` is True when the file is unreadable or ANY line
        is not a well-formed record (any asset — a damaged line's asset is
        unknowable). recovery refuses the normal restore in that case.
        """
        if not self.path.exists():
            return None, False
        try:
            content = self.path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            logger.warning("cut_state read failed: %s", e)
            return None, True
        damaged = False
        candidate: Optional[CutRecord] = None
        for line_no, raw_line in enumerate(content.splitlines(), start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                rec = _parse(json.loads(line))
            except (json.JSONDecodeError, RecursionError, KeyError, ValueError, TypeError) as e:
                logger.warning("cut_state %s:%d malformed line (%s)", self.path, line_no, e)
                damaged = True
                continue
            # Every line is validated above, whatever its asset; only then filter.
            if isinstance(rec, CutRecord):
                if rec.asset_id != asset_id:
                    continue
                if candidate is not None and candidate.platform != rec.platform:
                    logger.warning("cut_state %s:%d platform differs from earlier cut", self.path, line_no)
                    damaged = True
                prev = candidate.modified if candidate else ()
                prev_pairs = candidate.entries() if candidate else ()
                candidate = CutRecord(
                    asset_id=asset_id, cut_at=rec.cut_at, method=rec.method,
                    platform=rec.platform,
                    modified=prev + tuple(m for m in rec.modified if m not in prev),
                    pairs=prev_pairs + tuple(p for p in rec.entries() if p not in prev_pairs),
                )
            elif rec == asset_id:
                candidate = None
        return candidate, damaged

    def _append(self, rec: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, 0o700)
        except (OSError, NotImplementedError):
            pass
        existed = self.path.exists()
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        if not existed:
            try:
                os.chmod(self.path, 0o600)
            except (OSError, NotImplementedError):
                pass
