"""Hash-chain tests for telemetry/events_log.py (containment report export)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

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


def test_chain_all_ok_on_untouched_log(tmp_path: Path):
    log = EventLog(log_dir=tmp_path)
    for i in range(4):
        log.record_event(_event(f"event {i}"))
    results = verify_chain(log.events_path)
    assert len(results) == 4
    assert all(r["status"] == "ok" for r in results)


def test_first_record_chains_from_genesis(tmp_path: Path):
    log = EventLog(log_dir=tmp_path)
    log.record_event(_event())
    rec = json.loads(log.events_path.read_text().splitlines()[0])
    assert rec["prev_hash"] == GENESIS_HASH


def test_rewriting_a_record_is_detected(tmp_path: Path):
    log = EventLog(log_dir=tmp_path)
    for i in range(3):
        log.record_event(_event(f"event {i}"))
    lines = log.events_path.read_text().splitlines()
    tampered = json.loads(lines[1])
    tampered["detail"] = "attacker edited this"  # record_hash left stale
    lines[1] = json.dumps(tampered)
    log.events_path.write_text("\n".join(lines) + "\n")

    results = verify_chain(log.events_path)
    assert results[0]["status"] == "ok"
    assert results[1]["status"] == "corrupted"


def test_deleting_a_record_is_detected(tmp_path: Path):
    log = EventLog(log_dir=tmp_path)
    for i in range(3):
        log.record_event(_event(f"event {i}"))
    lines = log.events_path.read_text().splitlines()
    del lines[1]  # drop the middle record without touching the others
    log.events_path.write_text("\n".join(lines) + "\n")

    results = verify_chain(log.events_path)
    assert results[0]["status"] == "ok"
    assert results[1]["status"] == "chain_break"


def test_pre_chain_lines_are_legacy_not_tampered(tmp_path: Path):
    log = EventLog(log_dir=tmp_path)
    # Simulate a record written before this feature existed: no
    # prev_hash/record_hash at all.
    legacy = {
        "type": "trap_event", "source": "decoy_touch", "confidence": "high",
        "asset_id": "t-host", "decoy_ref": "t-host#0",
        "detected_at": datetime.now(timezone.utc).isoformat(),
        "detail": "pre-feature record", "op_class": "change",
    }
    log.log_dir.mkdir(parents=True, exist_ok=True)
    log.events_path.write_text(json.dumps(legacy) + "\n", encoding="utf-8")

    log.record_event(_event("first chained record"))
    results = verify_chain(log.events_path)
    assert results[0]["status"] == "legacy"
    # The chain starts fresh at genesis right after the legacy gap.
    assert results[1]["status"] == "ok"
    second = json.loads(log.events_path.read_text().splitlines()[1])
    assert second["prev_hash"] == GENESIS_HASH


def test_chain_survives_rotation(tmp_path: Path, monkeypatch):
    # `_append` always reads the outgoing file's last hash BEFORE calling
    # `_rotate_if_needed` (that ordering is the actual continuity
    # mechanism — see the comment in `_append`). Force rotation on every
    # call by lowering the default threshold, same code path as
    # production, just a smaller size trigger.
    original = EventLog.__dict__["_rotate_if_needed"].__func__
    monkeypatch.setattr(
        EventLog, "_rotate_if_needed",
        staticmethod(lambda path, max_bytes=0: original(path, max_bytes=0)),
    )
    log = EventLog(log_dir=tmp_path)
    log.record_event(_event("before rotation"))
    before_hash = json.loads(log.events_path.read_text().splitlines()[0])["record_hash"]

    log.record_event(_event("after rotation"))
    assert list(tmp_path.glob("events.jsonl.*")), "rotation did not run"
    after = json.loads(log.events_path.read_text().splitlines()[0])
    assert after["prev_hash"] == before_hash
