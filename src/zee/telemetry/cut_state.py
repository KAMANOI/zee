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

Compat mode: when the log file is missing or has no record for an
asset_id (pre-v0.3 deployments), the recovery layer falls back to the
v0.2 "enable everything" behaviour with a stderr warning. Once v0.3
is in steady state the warning identifies stale operator state that
needs cleanup.
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


@dataclass(frozen=True)
class CutRecord:
    asset_id: str
    cut_at: datetime
    method: str  # "full" / "egress"
    platform: str  # "linux" / "darwin" / "win32"
    modified: tuple[str, ...]


class CutStateLog:
    """Append-only JSON Lines log of ``cut`` and ``resolved`` events."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = path or default_cut_state_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, 0o700)
        except (OSError, NotImplementedError):
            pass

    def record_cut(
        self,
        *,
        asset_id: str,
        method: str,
        platform: str,
        modified: list[str],
    ) -> None:
        rec = {
            "type": "cut",
            "asset_id": asset_id,
            "cut_at": datetime.now(timezone.utc).isoformat(),
            "method": method,
            "platform": platform,
            "modified": list(modified),
        }
        self._append(rec)

    def mark_resolved(self, asset_id: str) -> None:
        rec = {
            "type": "resolved",
            "asset_id": asset_id,
            "resolved_at": datetime.now(timezone.utc).isoformat(),
        }
        self._append(rec)

    def latest_unresolved_for(self, asset_id: str) -> Optional[CutRecord]:
        """Return the most recent unresolved cut for ``asset_id``, or None.

        Walks the log in order. A ``cut`` record sets the candidate; a
        later ``resolved`` for the same asset clears it. The final
        non-None candidate at end-of-file is returned.
        """
        if not self.path.exists():
            return None
        try:
            content = self.path.read_text(encoding="utf-8")
        except OSError as e:
            logger.warning("cut_state read failed: %s", e)
            return None
        candidate: Optional[CutRecord] = None
        for line_no, raw_line in enumerate(content.splitlines(), start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as e:
                logger.warning(
                    "cut_state %s:%d malformed line, skipping (%s)",
                    self.path, line_no, e,
                )
                continue
            if rec.get("asset_id") != asset_id:
                continue
            rec_type = rec.get("type")
            if rec_type == "cut":
                try:
                    candidate = CutRecord(
                        asset_id=asset_id,
                        cut_at=datetime.fromisoformat(rec["cut_at"]),
                        method=rec.get("method", ""),
                        platform=rec.get("platform", ""),
                        modified=tuple(rec.get("modified", [])),
                    )
                except (KeyError, ValueError, TypeError) as e:
                    logger.warning(
                        "cut_state %s:%d malformed cut record (%s)",
                        self.path, line_no, e,
                    )
                    continue
            elif rec_type == "resolved":
                candidate = None
        return candidate

    def _append(self, rec: dict) -> None:
        existed = self.path.exists()
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        if not existed:
            try:
                os.chmod(self.path, 0o600)
            except (OSError, NotImplementedError):
                pass
