"""Tests for `zee export` (containment report export)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from zee.cli import main
from zee.events import TrapEvent
from zee.telemetry.events_log import EventLog


def _seed_events(log_dir: Path) -> None:
    log = EventLog(log_dir=log_dir)
    log.record_event(TrapEvent.make(
        source="decoy_touch", confidence="high", asset_id="t-host",
        decoy_path="/home/user/secret.txt",
        detail="write to /home/user/secret.txt", op_class="change",
    ))
    log.record_event(TrapEvent.make(
        source="decoy_touch", confidence="high", asset_id="t-host",
        decoy_path="/home/user/secret.txt",
        detail="open /home/user/secret.txt", op_class="read",
    ))


def test_export_writes_json_and_text(tmp_path: Path, monkeypatch):
    log_dir = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(log_dir))
    _seed_events(log_dir / "zee")

    out_prefix = tmp_path / "report"
    rc = main(["export", "--out", str(out_prefix)])
    assert rc == 0

    doc = json.loads((tmp_path / "report.json").read_text())
    assert doc["schema_version"] == "1"
    assert len(doc["events"]) == 2
    assert doc["chain_verification"]["events_jsonl"]["tamper_suspected"] is False
    assert "export_sha256" in doc
    assert (tmp_path / "report.txt").exists()


def test_export_redacts_detail_by_default(tmp_path: Path, monkeypatch):
    log_dir = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(log_dir))
    _seed_events(log_dir / "zee")

    main(["export", "--out", str(tmp_path / "report")])
    doc = json.loads((tmp_path / "report.json").read_text())
    assert all(e["detail"] == "[redacted]" for e in doc["events"])


def test_export_no_redact_keeps_detail(tmp_path: Path, monkeypatch):
    log_dir = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(log_dir))
    _seed_events(log_dir / "zee")

    main(["export", "--out", str(tmp_path / "report"), "--no-redact"])
    doc = json.loads((tmp_path / "report.json").read_text())
    assert any("secret.txt" in e["detail"] for e in doc["events"])


def test_export_exit_1_on_tampered_log(tmp_path: Path, monkeypatch, capsys):
    log_dir = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(log_dir))
    events_path = log_dir / "zee" / "events.jsonl"
    _seed_events(log_dir / "zee")

    lines = events_path.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["detail"] = "attacker edited this"
    lines[0] = json.dumps(rec)
    events_path.write_text("\n".join(lines) + "\n")

    rc = main(["export", "--out", str(tmp_path / "report")])
    assert rc == 1
    err = capsys.readouterr().err
    assert "WARNING" in err


def test_export_rejects_since_after_until(tmp_path: Path, monkeypatch, capsys):
    log_dir = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(log_dir))
    _seed_events(log_dir / "zee")

    rc = main([
        "export", "--out", str(tmp_path / "report"),
        "--since", "2026-12-01T00:00:00+00:00",
        "--until", "2026-01-01T00:00:00+00:00",
    ])
    assert rc != 0
    assert "Z702" in capsys.readouterr().err
