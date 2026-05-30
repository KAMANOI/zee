"""Event log (JSON Lines) and latency metrics (spec §7).

All measurements are real, recorded values. No estimates, no predictions
get written here as if they were observations.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from ..events import TrapEvent


def default_log_dir() -> Path:
    """Return the default directory for zee logs.

    Prefers XDG_STATE_HOME, then ~/.local/state/zee, falls back to ~/.zee.
    """
    env = os.environ.get("XDG_STATE_HOME")
    if env:
        return Path(env) / "zee"
    home = Path.home()
    local_state_parent = home / ".local" / "state"
    if local_state_parent.exists():
        return local_state_parent / "zee"
    return home / ".zee"


class EventLog:
    """Append-only JSON-Lines log of trap events and latency metrics."""

    def __init__(self, log_dir: Optional[Path] = None) -> None:
        self.log_dir = log_dir or default_log_dir()
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.events_path = self.log_dir / "events.jsonl"
        self.metrics_path = self.log_dir / "metrics.jsonl"

    def record_event(self, event: TrapEvent) -> None:
        record = {
            "type": "trap_event",
            "source": event.source,
            "confidence": event.confidence,
            "asset_id": event.asset_id,
            "decoy_path": event.decoy_path,
            "detected_at": event.detected_at.isoformat(),
            "detail": event.detail,
        }
        self._append(self.events_path, record)

    def record_latency(
        self,
        *,
        asset_id: str,
        detected_at: datetime,
        alert_sent_at: Optional[datetime],
        cut_done_at: Optional[datetime],
        cut_would_have_done_at: Optional[datetime],
        dry_run: bool,
        mode: str,
    ) -> None:
        record: dict[str, Any] = {
            "type": "latency",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "asset_id": asset_id,
            "mode": mode,
            "dry_run": dry_run,
            "detected_at": detected_at.isoformat(),
            "alert_sent_at": alert_sent_at.isoformat() if alert_sent_at else None,
            "cut_done_at": cut_done_at.isoformat() if cut_done_at else None,
            "cut_would_have_done_at": (
                cut_would_have_done_at.isoformat() if cut_would_have_done_at else None
            ),
        }
        # Real measured latencies only — derived if both ends exist.
        if alert_sent_at is not None:
            record["alert_latency_sec"] = (alert_sent_at - detected_at).total_seconds()
        end = cut_done_at or cut_would_have_done_at
        if end is not None:
            record["cut_latency_sec"] = (end - detected_at).total_seconds()
        self._append(self.metrics_path, record)

    def record_false_positive_marker(self, asset_id: str, note: str) -> None:
        """Operator-marked false positive (used to compute the counter in spec §7)."""
        record = {
            "type": "false_positive",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "asset_id": asset_id,
            "note": note,
        }
        self._append(self.metrics_path, record)

    def record_webhook_result(self, asset_id: str, ok: bool, detail: str) -> None:
        """Result of an async webhook dispatch (after fire-and-forget completes)."""
        record = {
            "type": "webhook_result",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "asset_id": asset_id,
            "ok": ok,
            "detail": detail,
        }
        self._append(self.metrics_path, record)

    @staticmethod
    def _append(path: Path, record: dict[str, Any]) -> None:
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
