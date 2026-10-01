"""Tests for `zee export` (containment report export)."""

from __future__ import annotations

import json
import os
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
    # Same owner-only policy as events.jsonl/metrics.jsonl: the export
    # carries the same event details, not world-readable 0644.
    assert (tmp_path / "report.json").stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "report.txt").stat().st_mode & 0o777 == 0o600


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


# --------------------------------------------------------------------------
# Output file safety (Codex #5 / #6)
# --------------------------------------------------------------------------

def _setup(tmp_path: Path, monkeypatch) -> Path:
    log_dir = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(log_dir))
    _seed_events(log_dir / "zee")
    return log_dir / "zee"


def test_export_refuses_existing_file_and_leaves_it_untouched(tmp_path, monkeypatch, capsys):
    _setup(tmp_path, monkeypatch)
    existing = tmp_path / "report.json"
    existing.write_text("precious")
    rc = main(["export", "--out", str(tmp_path / "report")])
    assert rc != 0
    assert "Z701" in capsys.readouterr().err
    assert existing.read_text() == "precious"
    assert not (tmp_path / "report.txt").exists()  # nothing written at all


def test_export_never_follows_a_symlink(tmp_path, monkeypatch, capsys):
    _setup(tmp_path, monkeypatch)
    victim = tmp_path / "victim.conf"
    victim.write_text("do not touch")
    (tmp_path / "report.txt").symlink_to(victim)
    rc = main(["export", "--out", str(tmp_path / "report")])
    assert rc != 0 and "Z701" in capsys.readouterr().err
    assert victim.read_text() == "do not touch"

    # --force replaces the link itself, never its target.
    rc = main(["export", "--out", str(tmp_path / "report"), "--force"])
    assert rc == 0
    assert victim.read_text() == "do not touch"
    assert not (tmp_path / "report.txt").is_symlink()
    assert (tmp_path / "report.txt").stat().st_mode & 0o777 == 0o600


def test_export_appends_extension_instead_of_replacing_it(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    assert main(["export", "--out", str(tmp_path / "report.2025")]) == 0
    assert main(["export", "--out", str(tmp_path / "report.2026")]) == 0
    for y in ("2025", "2026"):
        assert (tmp_path / f"report.{y}.json").exists()
        assert (tmp_path / f"report.{y}.txt").exists()


def test_export_failure_leaves_no_world_readable_partial(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    import zee.telemetry.report_export as rx

    def boom(export):
        raise OSError("disk full (simulated)")

    monkeypatch.setattr(rx, "render_text", boom)
    with pytest.raises(OSError):
        main(["export", "--out", str(tmp_path / "report")])
    assert not (tmp_path / "report.json").exists()
    for p in tmp_path.iterdir():
        if p.is_file():
            assert p.stat().st_mode & 0o077 == 0, f"{p} readable by others"


def test_export_write_error_is_z701_and_partial_is_0600(tmp_path, monkeypatch, capsys):
    _setup(tmp_path, monkeypatch)
    import zee.cli as cli

    real_link = os.link
    calls = []

    def flaky_link(src, dst, **kw):
        calls.append(dst)
        if len(calls) == 2:
            raise OSError("simulated failure on the second file")
        return real_link(src, dst, **kw)

    monkeypatch.setattr(cli.os, "link", flaky_link)
    rc = main(["export", "--out", str(tmp_path / "report")])
    assert rc != 0 and "Z701" in capsys.readouterr().err
    for p in tmp_path.iterdir():
        if p.is_file():
            assert p.stat().st_mode & 0o077 == 0, f"{p} readable by others"


def test_export_never_overwrites_a_file_created_during_the_run(tmp_path, monkeypatch, capsys):
    # Codex re-review #5: a file planted after the existence check but
    # before publishing must survive without --force.
    _setup(tmp_path, monkeypatch)
    import zee.cli as cli

    real_link = os.link

    def racing_link(src, dst, **kw):
        Path(dst).write_text("planted by someone else")
        return real_link(src, dst, **kw)

    monkeypatch.setattr(cli.os, "link", racing_link)
    rc = main(["export", "--out", str(tmp_path / "report")])
    assert rc != 0 and "Z701" in capsys.readouterr().err
    assert (tmp_path / "report.json").read_text() == "planted by someone else"


def test_export_leaves_no_temp_files_on_success(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    assert main(["export", "--out", str(tmp_path / "report")]) == 0
    assert sorted(p.name for p in tmp_path.iterdir() if p.is_file()) == [
        "report.json", "report.txt",
    ]


# --------------------------------------------------------------------------
# Period parsing (Codex #9)
# --------------------------------------------------------------------------

def _seed_at(log_dir: Path, *stamps: str) -> None:
    log = EventLog(log_dir=log_dir)
    for s in stamps:
        log.record_event(TrapEvent.make(
            source="decoy_touch", confidence="high", asset_id="t-host",
            decoy_path="/tmp/d", detail=f"at {s}", op_class="change",
            detected_at=datetime.fromisoformat(s),
        ))


@pytest.mark.parametrize(
    "bad",
    # "" : an unset shell variable must not silently mean "everything" (re-review #6)
    # 0001-01-01T00:00:00+09:00 : OverflowError when converted to UTC (re-review #7)
    ["not-a-date", "2026-13-01", "yesterday", "", "0001-01-01T00:00:00+09:00"],
)
def test_export_rejects_malformed_since(tmp_path, monkeypatch, capsys, bad):
    _setup(tmp_path, monkeypatch)
    rc = main(["export", "--out", str(tmp_path / "r"), "--since", bad])
    assert rc != 0 and "Z702" in capsys.readouterr().err
    assert not (tmp_path / "r.json").exists()


def test_export_compares_instants_not_strings(tmp_path, monkeypatch):
    # 09:00+09:00 == 00:00Z, which IS before 01:00Z — previously rejected.
    _setup(tmp_path, monkeypatch)
    rc = main([
        "export", "--out", str(tmp_path / "r"),
        "--since", "2026-10-01T09:00:00+09:00",
        "--until", "2026-10-01T01:00:00+00:00",
    ])
    assert rc == 0


def test_export_period_filter_tz_and_date_only(tmp_path, monkeypatch):
    log_dir = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(log_dir))
    _seed_at(
        log_dir / "zee",
        "2026-09-30T23:59:59+00:00",
        "2026-10-01T00:00:00+00:00",
        "2026-10-01T12:00:00+00:00",
        "2026-10-02T00:00:01+00:00",
    )
    # Date only = 00:00 UTC; no TZ = UTC.
    assert main([
        "export", "--out", str(tmp_path / "r"),
        "--since", "2026-10-01", "--until", "2026-10-02T00:00:00",
    ]) == 0
    doc = json.loads((tmp_path / "r.json").read_text())
    assert doc["events_total"] == 2
    assert doc["period"]["since"] == "2026-10-01T00:00:00+00:00"


def test_export_includes_rotated_segments(tmp_path, monkeypatch):
    log_dir = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(log_dir))
    original = EventLog.__dict__["_rotate_if_needed"].__func__
    monkeypatch.setattr(
        EventLog, "_rotate_if_needed",
        staticmethod(lambda path, max_bytes=0: original(path, max_bytes=0)),
    )
    _seed_at(log_dir / "zee", "2026-09-01T00:00:00+00:00", "2026-10-01T00:00:00+00:00")
    assert list((log_dir / "zee").glob("events.jsonl.*"))
    assert main(["export", "--out", str(tmp_path / "r"), "--until", "2026-09-15"]) == 0
    doc = json.loads((tmp_path / "r.json").read_text())
    assert doc["events_total"] == 1
    assert doc["chain_verification"]["events_jsonl"]["status"] == "ok"
    assert len(doc["chain_verification"]["events_jsonl"]["files"]) == 2


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0, reason="root ignores modes"
)
def test_export_unreadable_log_is_unverifiable_and_nonzero(tmp_path, monkeypatch, capsys):
    zee_dir = _setup(tmp_path, monkeypatch)
    ev = zee_dir / "events.jsonl"
    ev.chmod(0o000)
    try:
        rc = main(["export", "--out", str(tmp_path / "r")])
    finally:
        ev.chmod(0o600)
    assert rc == 1
    assert "UNVERIFIABLE" in capsys.readouterr().err
    doc = json.loads((tmp_path / "r.json").read_text())
    assert doc["chain_verification"]["events_jsonl"]["status"] == "unverifiable"
    assert "検証不能" in (tmp_path / "r.txt").read_text()


def test_export_summary_does_not_claim_a_cut(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    main(["export", "--out", str(tmp_path / "r")])
    s = json.loads((tmp_path / "r.json").read_text())["report_fields"]["incident_summary_auto"]
    assert "遮断を行い" not in s and "自動遮断のみを行い" not in s
    assert "dry_run" in s
