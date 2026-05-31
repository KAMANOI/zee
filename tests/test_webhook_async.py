"""Webhook fire-and-forget — cut must not be delayed by network I/O.

Reviewer-identified high-severity issue: the previous sync webhook
could block cut for the full timeout window. The fix runs webhook
on a daemon thread; this test enforces that the responder returns
before the webhook completes.
"""

from __future__ import annotations

import json
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from zee.config.schema import AssetProfile
from zee.events import TrapEvent
from zee.responder.sequence import handle
from zee.telemetry.events_log import EventLog


def _asset() -> AssetProfile:
    return AssetProfile(
        id="t-host",
        type="workstation",
        overnight_active=False,
        decoy_paths=("/tmp/decoy",),
        response_mode="notify",  # avoid actually invoking cut backends
        cut_method="full",
    )


def test_webhook_does_not_block_responder():
    """Even with a slow webhook, the responder returns within ~100 ms."""
    webhook_entered = threading.Event()
    webhook_release = threading.Event()
    webhook_completed = threading.Event()

    def slow_sender(title, body):
        webhook_entered.set()
        webhook_release.wait(timeout=2.0)  # blocks until we release
        webhook_completed.set()
        return True, "HTTP 200"

    event = TrapEvent.make(
        source="decoy_touch", confidence="high",
        asset_id="t-host", decoy_path="/tmp/decoy",
        detail="test", op_class="change",
        detected_at=datetime.now(timezone.utc),
    )

    with tempfile.TemporaryDirectory() as td:
        log = EventLog(log_dir=Path(td))
        start = time.monotonic()
        result = handle(event, _asset(),
                        dry_run=True, event_log=log,
                        webhook_sender=slow_sender)
        elapsed = time.monotonic() - start
        # Responder must return promptly; the webhook is on another thread.
        assert elapsed < 0.5, f"responder took {elapsed:.2f}s; webhook blocked the cut path"
        # Webhook was dispatched but not awaited.
        assert webhook_entered.wait(timeout=1.0), "webhook never started"
        assert webhook_completed.is_set() is False, "webhook finished synchronously (it shouldn't)"
        # Release the webhook and let it finish.
        webhook_release.set()
        assert webhook_completed.wait(timeout=2.0), "webhook never completed"

        # Allow the daemon thread time to write its result line.
        for _ in range(20):
            metrics = log.metrics_path.read_text().strip().split("\n") if log.metrics_path.exists() else []
            if any('"type": "webhook_result"' in line for line in metrics):
                break
            time.sleep(0.05)
        webhook_records = [
            json.loads(line) for line in metrics
            if line and '"type": "webhook_result"' in line
        ]
        assert len(webhook_records) == 1
        assert webhook_records[0]["ok"] is True

        # The synchronous return value reports "dispatched" (None).
        assert result.notified_remote is None
