"""Dry-run demo — synthesize a decoy touch and walk through the sequence.

No real watcher, no real cut, no network. Useful on every OS to verify
that the responder, notifier, policy, and event log are wired correctly.

Usage:
    python examples/demo_dry_run.py
"""

from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path

from zee.config.schema import AssetProfile
from zee.events import TrapEvent
from zee.responder.sequence import handle
from zee.telemetry.events_log import EventLog


def main() -> int:
    asset = AssetProfile(
        id="demo-host",
        type="workstation",
        overnight_active=False,
        decoy_paths=("/tmp/zee-demo/.env",),
        response_mode="auto",          # auto so we exercise the contain branch
        cut_method="egress",
    )
    event = TrapEvent.make(
        source="decoy_touch",
        confidence="high",
        asset_id=asset.id,
        decoy_path="/tmp/zee-demo/.env",
        detail="decoy write (demo)",
        op_class="change",   # demo a change-class event to exercise the cut path
        detected_at=datetime.now(timezone.utc),
    )

    with tempfile.TemporaryDirectory() as td:
        log = EventLog(log_dir=Path(td))
        result = handle(event, asset, dry_run=True, event_log=log)
        print("=== demo result ===")
        print(f"asset             : {result.asset_id}")
        print(f"mode              : {result.mode}")
        print(f"cut_executed      : {result.cut_executed}")
        print(f"would_have_cut    : {result.cut_would_have_been_executed}")
        print(f"cut_detail        : {result.cut_detail}")
        print(f"notified_locally  : {result.notified_locally}")
        print(f"notified_remote   : {result.notified_remote}")
        print()
        print(f"events log    : {log.events_path}")
        print(f"metrics log   : {log.metrics_path}")
        print()
        print("events.jsonl content:")
        print(log.events_path.read_text())
        print("metrics.jsonl content:")
        print(log.metrics_path.read_text())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
