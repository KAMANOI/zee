"""Evidence-log failures must never stop notification / containment.

responder.sequence.handle() calls event_log.record_event() BEFORE the
local notification and the cut. Whatever state events.jsonl is in —
unparseable tail, wrong types, invalid UTF-8, unreadable, unwritable —
handle() must still notify and (in contain mode) cut.
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

import zee.responder.sequence as seq
from zee.config.schema import AssetProfile
from zee.events import TrapEvent
from zee.telemetry.events_log import EventLog


def _event() -> TrapEvent:
    return TrapEvent.make(
        source="decoy_touch", confidence="high", asset_id="t-host",
        decoy_path="/tmp/decoy", detail="write (test)", op_class="change",
        detected_at=datetime.now(timezone.utc),
    )


def _asset() -> AssetProfile:
    return AssetProfile(
        id="t-host", type="workstation", overnight_active=False,
        decoy_paths=("/tmp/decoy",), response_mode="auto", cut_method="egress",
    )


BROKEN_TAILS = [
    b"null\n",
    b"[]\n",
    b'{"record_hash": 5}\n',
    b'{"record_hash": null, "prev_hash": []}\n',
    b"\xff\xfe\xfa not utf-8\n",
    b'{"type": "trap_ev',  # torn write, no newline
]


def _run(monkeypatch, log: EventLog):
    notified, cuts = [], []
    monkeypatch.setattr(seq, "notify_local", lambda t, b: notified.append(t) or True)
    monkeypatch.setattr(seq, "cut_egress", lambda **k: cuts.append(k) or (True, "stub"))
    result = seq.handle(_event(), _asset(), dry_run=False, event_log=log)
    return result, notified, cuts


@pytest.mark.parametrize("tail", BROKEN_TAILS)
def test_broken_log_tail_does_not_stop_notify_or_cut(tmp_path: Path, monkeypatch, tail):
    log = EventLog(log_dir=tmp_path)
    log.events_path.write_bytes(tail)
    log.metrics_path.write_bytes(tail)
    result, notified, cuts = _run(monkeypatch, log)
    assert notified, "local notification must still happen"
    assert len(cuts) == 1, "containment must still run"
    assert result.cut_executed is True


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0, reason="root ignores modes"
)
def test_unreadable_and_unwritable_log_does_not_stop_notify_or_cut(tmp_path: Path, monkeypatch):
    log = EventLog(log_dir=tmp_path)
    log.events_path.write_text("{}\n")
    log.events_path.chmod(0o000)
    log.metrics_path.write_text("{}\n")
    log.metrics_path.chmod(0o000)
    try:
        result, notified, cuts = _run(monkeypatch, log)
    finally:
        log.events_path.chmod(0o600)
        log.metrics_path.chmod(0o600)
    assert notified and len(cuts) == 1 and result.cut_executed is True


def test_failure_inside_append_is_swallowed_and_logged(tmp_path: Path, monkeypatch, caplog):
    import zee.telemetry.events_log as el

    def boom(path):
        raise RuntimeError("simulated tail failure")

    monkeypatch.setattr(el, "_chain_tail", boom)
    log = EventLog(log_dir=tmp_path)
    result, notified, cuts = _run(monkeypatch, log)
    assert notified and len(cuts) == 1
    assert "simulated tail failure" in caplog.text
    # The record is still written (chained from GENESIS → visible as a break later).
    assert log.events_path.read_text(encoding="utf-8").strip()


def test_held_file_lock_does_not_stop_notify_or_cut(tmp_path: Path, monkeypatch, caplog):
    """Codex re-review #1: another fd (e.g. a stuck process) holds the log's
    flock. handle() must give up on the evidence record after the bounded
    wait and still notify and cut."""
    fcntl = pytest.importorskip("fcntl")
    import zee.telemetry.events_log as el

    monkeypatch.setattr(el, "_LOCK_TIMEOUT_SEC", 0.2)
    log = EventLog(log_dir=tmp_path)
    holders = []
    for name in ("events.jsonl", "metrics.jsonl"):
        fd = os.open(tmp_path / f".{name}.lock", os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        holders.append(fd)
    try:
        t0 = time.monotonic()
        result, notified, cuts = _run(monkeypatch, log)
        elapsed = time.monotonic() - t0
    finally:
        for fd in holders:
            os.close(fd)
    assert notified and len(cuts) == 1 and result.cut_executed is True
    assert elapsed < 5
    assert "not acquired within" in caplog.text


def test_held_thread_lock_does_not_stop_notify_or_cut(tmp_path: Path, monkeypatch, caplog):
    import zee.telemetry.events_log as el

    monkeypatch.setattr(el, "_LOCK_TIMEOUT_SEC", 0.2)
    log = EventLog(log_dir=tmp_path)
    assert el._APPEND_LOCK.acquire(timeout=1)
    try:
        result, notified, cuts = _run(monkeypatch, log)
    finally:
        el._APPEND_LOCK.release()
    assert notified and len(cuts) == 1 and result.cut_executed is True
    assert "not acquired within" in caplog.text
