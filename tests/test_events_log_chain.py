"""Hash-chain tests for telemetry/events_log.py (containment report export)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest

import zee.telemetry.events_log as el
from zee.events import TrapEvent
from zee.telemetry.events_log import EventLog, GENESIS_HASH, verify_chain


def _event(detail: str = "test") -> TrapEvent:
    return TrapEvent.make(
        source="decoy_touch",
        confidence="high",
        asset_id="t-host",
        decoy_path="/tmp/decoy",
        detail=detail,
        op_class="change",
        detected_at=datetime.now(timezone.utc),
    )


def _statuses(path: Path) -> list[str]:
    return [r["status"] for r in verify_chain(path)["results"]]


def _seed(tmp_path: Path, n: int = 3) -> EventLog:
    log = EventLog(log_dir=tmp_path)
    for i in range(n):
        log.record_event(_event(f"event {i}"))
    return log


def _rewrite(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_chain_all_ok_on_untouched_log(tmp_path: Path):
    log = _seed(tmp_path, 4)
    v = verify_chain(log.events_path)
    assert v["read_error"] is None
    assert _statuses(log.events_path) == ["ok"] * 4


def test_first_record_chains_from_genesis(tmp_path: Path):
    log = _seed(tmp_path, 1)
    rec = json.loads(log.events_path.read_text().splitlines()[0])
    assert rec["prev_hash"] == GENESIS_HASH


def test_rewriting_a_record_is_detected_and_localised(tmp_path: Path):
    log = _seed(tmp_path)
    lines = log.events_path.read_text().splitlines()
    tampered = json.loads(lines[1])
    tampered["detail"] = "attacker edited this"  # record_hash left stale
    lines[1] = json.dumps(tampered)
    _rewrite(log.events_path, lines)
    assert _statuses(log.events_path) == ["ok", "corrupted", "ok"]


def test_deleting_a_middle_record_is_detected(tmp_path: Path):
    log = _seed(tmp_path)
    lines = log.events_path.read_text().splitlines()
    del lines[1]
    _rewrite(log.events_path, lines)
    assert _statuses(log.events_path) == ["ok", "chain_break"]


def test_deleting_the_first_record_is_detected(tmp_path: Path):
    log = _seed(tmp_path)
    lines = log.events_path.read_text().splitlines()
    del lines[0]
    _rewrite(log.events_path, lines)
    assert _statuses(log.events_path) == ["head_missing", "ok"]


def test_truncating_the_tail_is_NOT_detected(tmp_path: Path):
    # Documented limit (README / chain_verification.note): a shorter chain
    # is still a valid chain. This test pins the limit so the docs stay honest.
    log = _seed(tmp_path)
    lines = log.events_path.read_text().splitlines()
    _rewrite(log.events_path, lines[:-1])
    assert _statuses(log.events_path) == ["ok", "ok"]


def test_stripping_hashes_mid_chain_is_not_accepted_as_legacy(tmp_path: Path):
    # Codex #1 repro: previously ok, legacy, ok (the edit went unnoticed).
    log = _seed(tmp_path)
    lines = log.events_path.read_text().splitlines()
    rec = json.loads(lines[1])
    del rec["record_hash"], rec["prev_hash"]
    rec["detail"] = "rewritten"
    lines[1] = json.dumps(rec)
    _rewrite(log.events_path, lines)
    assert _statuses(log.events_path) == ["ok", "legacy_after_chain", "chain_break"]


def test_removing_only_record_hash_is_corrupted(tmp_path: Path):
    log = _seed(tmp_path)
    lines = log.events_path.read_text().splitlines()
    rec = json.loads(lines[1])
    del rec["record_hash"]
    lines[1] = json.dumps(rec)
    _rewrite(log.events_path, lines)
    assert _statuses(log.events_path)[1] == "corrupted"


def test_pre_chain_lines_are_legacy_not_tampered(tmp_path: Path):
    log = EventLog(log_dir=tmp_path)
    legacy = {
        "type": "trap_event", "source": "decoy_touch", "confidence": "high",
        "asset_id": "t-host", "decoy_ref": "t-host#0",
        "detected_at": datetime.now(timezone.utc).isoformat(),
        "detail": "pre-feature record", "op_class": "change",
    }
    log.events_path.write_text(json.dumps(legacy) + "\n", encoding="utf-8")
    log.record_event(_event("first chained record"))
    assert _statuses(log.events_path) == ["legacy", "ok"]
    second = json.loads(log.events_path.read_text().splitlines()[1])
    assert second["prev_hash"] == GENESIS_HASH


def test_partial_last_line_is_reported_separately_then_isolated(tmp_path: Path):
    log = _seed(tmp_path, 2)
    good_last = json.loads(log.events_path.read_text().splitlines()[-1])["record_hash"]
    with log.events_path.open("a") as f:
        f.write('{"type": "trap_ev')  # crash mid-write, no newline
    v = verify_chain(log.events_path)
    assert [r["status"] for r in v["results"]] == ["ok", "ok", "partial"]

    # The next append must not glue onto the torn line, and must chain
    # from the last GOOD record.
    log.record_event(_event("after crash"))
    lines = log.events_path.read_text().splitlines()
    assert lines[2] == '{"type": "trap_ev'
    assert json.loads(lines[3])["prev_hash"] == good_last
    assert _statuses(log.events_path) == ["ok", "ok", "corrupted", "ok"]


def _force_rotation(monkeypatch):
    original = EventLog.__dict__["_rotate_if_needed"].__func__
    monkeypatch.setattr(
        EventLog, "_rotate_if_needed",
        staticmethod(lambda path, max_bytes=0: original(path, max_bytes=0)),
    )


def test_chain_survives_rotation_and_verifies_across_segments(tmp_path: Path, monkeypatch):
    log = _seed(tmp_path, 1)
    before_hash = json.loads(log.events_path.read_text().splitlines()[0])["record_hash"]
    _force_rotation(monkeypatch)
    log.record_event(_event("after rotation"))
    rotated = list(tmp_path.glob("events.jsonl.*"))
    assert rotated, "rotation did not run"
    after = json.loads(log.events_path.read_text().splitlines()[0])
    assert after["prev_hash"] == before_hash
    v = verify_chain(log.events_path)
    assert v["files"] == [rotated[0].name, "events.jsonl"]
    assert [r["status"] for r in v["results"]] == ["ok", "ok"]


def test_missing_rotated_segment_is_detected(tmp_path: Path, monkeypatch):
    log = _seed(tmp_path, 1)
    _force_rotation(monkeypatch)
    log.record_event(_event("after rotation"))
    rotated = next(tmp_path.glob("events.jsonl.*"))
    rotated.rename(tmp_path / "moved-away")  # operator/attacker removed it
    assert _statuses(log.events_path) == ["head_missing"]


def test_rotation_never_overwrites_a_same_second_segment(tmp_path: Path, monkeypatch):
    class _Frozen(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 10, 1, 0, 0, 0, tzinfo=timezone.utc)

    monkeypatch.setattr(el, "datetime", _Frozen)
    p = tmp_path / "events.jsonl"
    for i in range(3):
        p.write_text(f"segment {i}\n")
        EventLog._rotate_if_needed(p, max_bytes=0)
    names = sorted(x.name for x in tmp_path.glob("events.jsonl.*"))
    assert names == [
        "events.jsonl.20261001_000000",
        "events.jsonl.20261001_000000_001",
        "events.jsonl.20261001_000000_002",
    ]
    assert [(tmp_path / n).read_text() for n in names] == [
        "segment 0\n", "segment 1\n", "segment 2\n",
    ]


def test_concurrent_thread_appends_keep_the_chain(tmp_path: Path):
    log = EventLog(log_dir=tmp_path)

    def worker(k: int) -> None:
        for i in range(20):
            log.record_webhook_result(f"a{k}", True, f"{k}-{i}")
            log.record_latency(
                asset_id=f"a{k}", detected_at=datetime.now(timezone.utc),
                alert_sent_at=None, cut_done_at=None,
                cut_would_have_done_at=None, dry_run=True, mode="notify",
            )

    threads = [threading.Thread(target=worker, args=(k,)) for k in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    st = _statuses(log.metrics_path)
    assert len(st) == 160 and set(st) == {"ok"}


def test_concurrent_process_appends_keep_the_chain(tmp_path: Path):
    code = (
        "import sys; from pathlib import Path;"
        "from zee.telemetry.events_log import EventLog;"
        "log = EventLog(log_dir=Path(sys.argv[1]));"
        "[log.record_webhook_result('p', True, str(i)) for i in range(40)]"
    )
    procs = [
        subprocess.Popen([sys.executable, "-c", code, str(tmp_path)]) for _ in range(3)
    ]
    assert all(p.wait(timeout=60) == 0 for p in procs)
    st = _statuses(tmp_path / "metrics.jsonl")
    assert len(st) == 120 and set(st) == {"ok"}


def test_append_reads_only_the_tail(tmp_path: Path, monkeypatch):
    # With a window much smaller than the file, the writer must still find
    # the last chained record (and discard the cut-off first piece).
    monkeypatch.setattr(el, "_TAIL_WINDOW", 1024)
    log = _seed(tmp_path, 30)
    assert log.events_path.stat().st_size > 10 * 1024
    log.record_event(_event("after"))
    assert _statuses(log.events_path) == ["ok"] * 31


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0, reason="root ignores modes"
)
def test_unreadable_log_is_reported_as_read_error(tmp_path: Path):
    log = _seed(tmp_path, 1)
    log.events_path.chmod(0o000)
    try:
        v = verify_chain(log.events_path)
    finally:
        log.events_path.chmod(0o600)
    assert v["read_error"] is not None
