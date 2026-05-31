"""macOS watcher smoke test — kqueue change detection (spec §9).

Skipped on non-Darwin platforms.
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "darwin",
    reason="MacOSKqueueWatcher requires darwin",
)


def test_capability_unconfigured_declares_modify_only():
    """v0.2 default: no ZEE_CANARY_BASE_URL → canary fallback is False
    and the notes string carries the configuration hint."""
    from zee.watcher.backend_macos import MacOSKqueueWatcher
    w = MacOSKqueueWatcher()
    cap = w.capability()
    assert cap.detects_modify is True
    assert cap.detects_open is False
    assert cap.detects_read is False
    assert cap.uses_canary_fallback is False
    assert "ZEE_CANARY_BASE_URL" in cap.notes


def test_capability_with_canary_declares_canary_fallback():
    """v0.2 wired: canary_configured=True → canary fallback is True
    and read detection is described as 'delegated to canary URLs'."""
    from zee.watcher.backend_macos import MacOSKqueueWatcher
    w = MacOSKqueueWatcher(canary_configured=True)
    cap = w.capability()
    assert cap.detects_modify is True
    assert cap.uses_canary_fallback is True
    assert "canary URLs" in cap.notes


def test_modify_fires_event(tmp_path):
    from zee.watcher.backend_macos import MacOSKqueueWatcher

    decoy = tmp_path / "decoy.env"
    decoy.write_text("initial=1\n")

    received: list = []
    received_event = threading.Event()

    def on_event(evt):
        received.append(evt)
        received_event.set()

    w = MacOSKqueueWatcher()
    w.start([str(decoy)], "t-asset", on_event)
    try:
        time.sleep(0.1)
        # Modify the file to trigger NOTE_WRITE.
        with decoy.open("a") as f:
            f.write("modified\n")
        assert received_event.wait(timeout=2.0), "no event received within 2s"
        assert received[0].asset_id == "t-asset"
        assert received[0].source == "decoy_touch"
        assert received[0].confidence == "high"
        assert "decoy" in received[0].detail
    finally:
        w.stop()
