"""Tests for `zee incident-report` (police/PPC handoff document bundling).

See docs/design/incident-report.md. Builds a real `zee export` output
(not a hand-typed fixture) so the input contract tested here is the
one `zee export` actually produces.
"""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path

import pytest

from zee.cli import main
from zee.errors import ZeeError
from zee.events import TrapEvent
from zee.report.incident_report import (
    DilutionSummary,
    build_incident_report,
    load_canary_hits,
    load_export,
    render_html,
    render_text,
)
from zee.telemetry.events_log import EventLog

POSIX_MODES = os.name != "nt"


def _mode(p: Path) -> int:
    return p.stat().st_mode & 0o777 if POSIX_MODES else 0o600


def _make_export(tmp_path: Path, monkeypatch) -> Path:
    log_dir = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(log_dir))
    log = EventLog(log_dir=log_dir / "zee")
    log.record_event(TrapEvent.make(
        source="decoy_touch", confidence="high", asset_id="t-host",
        decoy_path="/home/user/secret.txt",
        detail="write to /home/user/secret.txt", op_class="change",
    ))
    export_prefix = tmp_path / "export"
    rc = main(["export", "--out", str(export_prefix)])
    assert rc == 0
    return Path(str(export_prefix) + ".json")


def _canary_hits_file(tmp_path: Path, name: str, rows: list[dict]) -> Path:
    p = tmp_path / name
    p.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n", encoding="utf-8")
    return p


def test_incident_report_police_vs_ppc_switch(tmp_path: Path, monkeypatch):
    export_path = _make_export(tmp_path, monkeypatch)
    export = load_export(export_path)

    police_doc = build_incident_report(export=export, recipient="police")
    ppc_doc = build_incident_report(export=export, recipient="ppc")

    assert "police_fields" in police_doc and "ppc_statutory_items" not in police_doc
    assert "ppc_statutory_items" in ppc_doc and "police_fields" not in ppc_doc
    assert "9 その他参考となる事項" in ppc_doc["ppc_statutory_items"]

    police_text = render_text(police_doc)
    ppc_text = render_text(ppc_doc)
    # The body (report_fields / statutory items) must only carry the chosen
    # lane; the reference footer (代表指示: 末尾に両方) always lists both.
    police_body = police_text.split("## 参照窓口", 1)[0]
    assert "警察" in police_body and "個人情報保護委員会" not in police_body
    assert "個人情報保護委員会" in ppc_text
    for text in (police_text, ppc_text):
        footer = text.split("## 参照窓口", 1)[1]
        assert "警察" in footer and "個人情報保護委員会" in footer
        assert "03-6457-9680" in footer


def test_unknown_recipient_rejected(tmp_path: Path, monkeypatch):
    export = load_export(_make_export(tmp_path, monkeypatch))
    with pytest.raises(ZeeError) as e:
        build_incident_report(export=export, recipient="fbi")
    assert e.value.code == "Z1001"


def test_canary_hits_bundled_across_multiple_files(tmp_path: Path):
    f1 = _canary_hits_file(tmp_path, "hits1.jsonl", [
        {"ts": "2026-10-08T00:00:00+00:00", "remote_ip": "203.0.113.1", "token": "aaa"},
    ])
    f2 = _canary_hits_file(tmp_path, "hits2.jsonl", [
        {"ts": "2026-10-09T00:00:00+00:00", "remote_ip": "203.0.113.2", "token": "bbb"},
        {"ts": "2026-10-09T01:00:00+00:00", "remote_ip": "203.0.113.2", "token": "bbb"},
    ])
    hits = load_canary_hits([f1, f2])
    assert len(hits) == 3

    from zee.report.incident_report import _canary_summary
    summary = _canary_summary(hits)
    assert summary["count"] == 3
    assert summary["unique_tokens"] == 2
    assert summary["first_seen"] == "2026-10-08T00:00:00+00:00"
    assert summary["last_seen"] == "2026-10-09T01:00:00+00:00"


def test_malformed_canary_hits_file_rejected(tmp_path: Path):
    bad = tmp_path / "bad.jsonl"
    bad.write_text("not json\n", encoding="utf-8")
    with pytest.raises(ZeeError) as e:
        load_canary_hits([bad])
    assert e.value.code == "Z1002"


def test_canary_hits_missing_required_fields_rejected(tmp_path: Path):
    bad = tmp_path / "bad.jsonl"
    bad.write_text(json.dumps({"remote_ip": "1.2.3.4"}) + "\n", encoding="utf-8")
    with pytest.raises(ZeeError) as e:
        load_canary_hits([bad])
    assert e.value.code == "Z1002"


def test_canary_hit_with_non_string_token_rejected(tmp_path: Path):
    bad = tmp_path / "bad.jsonl"
    bad.write_text(json.dumps({"ts": "2026-10-09T00:00:00+00:00", "token": ["a"]}) + "\n", encoding="utf-8")
    with pytest.raises(ZeeError) as e:
        load_canary_hits([bad])
    assert e.value.code == "Z1002"


def test_canary_hit_with_unparseable_ts_rejected(tmp_path: Path):
    bad = tmp_path / "bad.jsonl"
    bad.write_text(json.dumps({"ts": "not-a-timestamp", "token": "aaa"}) + "\n", encoding="utf-8")
    with pytest.raises(ZeeError) as e:
        load_canary_hits([bad])
    assert e.value.code == "Z1002"


def test_canary_summary_orders_by_instant_not_string(tmp_path: Path):
    # 09:00+09:00 == 00:00 UTC, which is BEFORE 01:00+00:00 — a naive
    # string sort would get this backwards (found in external review).
    from zee.report.incident_report import _canary_summary

    hits = [
        {"ts": "2026-10-09T01:00:00+00:00", "token": "later"},
        {"ts": "2026-10-09T09:00:00+09:00", "token": "earlier"},
    ]
    summary = _canary_summary(hits)
    assert summary["first_seen"] == "2026-10-09T09:00:00+09:00"
    assert summary["last_seen"] == "2026-10-09T01:00:00+00:00"


def test_export_with_null_report_fields_rejected(tmp_path: Path):
    bad = tmp_path / "bad_export.json"
    bad.write_text(json.dumps({"schema_version": "1", "report_fields": None}), encoding="utf-8")
    with pytest.raises(ZeeError) as e:
        load_export(bad)
    assert e.value.code == "Z1004"


def test_export_with_unsupported_schema_version_rejected(tmp_path: Path):
    bad = tmp_path / "bad_export.json"
    bad.write_text(json.dumps({"schema_version": "99", "report_fields": {}}), encoding="utf-8")
    with pytest.raises(ZeeError) as e:
        load_export(bad)
    assert e.value.code == "Z1004"


def test_output_cannot_collide_with_input_export_file(tmp_path: Path, monkeypatch):
    export_path = _make_export(tmp_path, monkeypatch)
    out_prefix = Path(str(export_path)[: -len(".json")])  # same stem as the export
    assert out_prefix.with_suffix(".json") == export_path

    rc = main([
        "incident-report",
        "--export-json", str(export_path),
        "--recipient", "police",
        "--out", str(out_prefix),
        "--force",
    ])
    assert rc != 0
    # The original evidence file must survive untouched.
    original = json.loads(export_path.read_text(encoding="utf-8"))
    assert "events" in original


def test_report_includes_full_event_detail(tmp_path: Path, monkeypatch):
    export = load_export(_make_export(tmp_path, monkeypatch))
    doc = build_incident_report(export=export, recipient="police")
    assert len(doc["containment_export"]["events"]) == 1
    assert doc["containment_export"]["events"][0]["asset_id"] == "t-host"


def test_dilution_count_inconsistent_rejected():
    with pytest.raises(ZeeError) as e:
        DilutionSummary(leaked_total=5, dummy_matched=10)
    assert e.value.code == "Z1003"

    with pytest.raises(ZeeError):
        DilutionSummary(leaked_total=5, dummy_matched=-1)


def test_dilution_upper_bound_reflected_in_ppc_report(tmp_path: Path, monkeypatch):
    export = load_export(_make_export(tmp_path, monkeypatch))
    dilution = DilutionSummary(leaked_total=100, dummy_matched=30)
    doc = build_incident_report(export=export, recipient="ppc", dilution=dilution)
    assert doc["dilution"]["real_upper_bound"] == 70
    text = render_text(doc)
    assert "70" in text
    # The ledger/seed never enter this module's API at all — only two ints do.
    import inspect
    assert "ledger" not in inspect.signature(build_incident_report).parameters
    assert "seed" not in inspect.signature(build_incident_report).parameters


def test_export_file_required_rejects_garbage(tmp_path: Path):
    garbage = tmp_path / "not_an_export.json"
    garbage.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
    with pytest.raises(ZeeError) as e:
        load_export(garbage)
    assert e.value.code == "Z1004"


def test_chain_verification_surfaced_in_report(tmp_path: Path, monkeypatch):
    export = load_export(_make_export(tmp_path, monkeypatch))
    doc = build_incident_report(export=export, recipient="police")
    assert doc["containment_export"]["chain_verification"]["events_jsonl"]["status"] == "ok"
    assert "改ざん検知" in render_text(doc)


def test_bundling_is_operator_scoped_not_automatic(tmp_path: Path, monkeypatch):
    export = load_export(_make_export(tmp_path, monkeypatch))
    doc = build_incident_report(export=export, recipient="police")
    assert "自動的に同一主体と" in doc["bundling_note"]


def test_html_output_is_dependency_free_and_escaped(tmp_path: Path, monkeypatch):
    export = load_export(_make_export(tmp_path, monkeypatch))
    doc = build_incident_report(export=export, recipient="police", incident_label="<script>x</script>")
    html = render_html(doc)
    assert "<script>x</script>" not in html
    assert "&lt;script&gt;" in html


def test_cli_writes_three_files_owner_only(tmp_path: Path, monkeypatch):
    export_path = _make_export(tmp_path, monkeypatch)
    out_prefix = tmp_path / "incident"
    rc = main([
        "incident-report",
        "--export-json", str(export_path),
        "--recipient", "ppc",
        "--out", str(out_prefix),
    ])
    assert rc == 0
    for suffix in (".json", ".txt", ".html"):
        p = Path(str(out_prefix) + suffix)
        assert p.exists()
        assert _mode(p) == 0o600


def test_cli_rejects_bad_recipient(tmp_path: Path, monkeypatch, capsys):
    export_path = _make_export(tmp_path, monkeypatch)
    # argparse's choices=("police", "ppc") rejects this before _cmd_incident_report runs.
    with pytest.raises(SystemExit):
        main([
            "incident-report",
            "--export-json", str(export_path),
            "--recipient", "fbi",
            "--out", str(tmp_path / "incident"),
        ])


# --- The structural guarantee: this module cannot send anything anywhere. ---

_FORBIDDEN_IMPORTS = {"urllib", "http", "http.client", "socket", "smtplib", "requests", "zee.notifier"}


def _imported_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def test_no_network_imports():
    import zee.report.incident_report as mod
    import zee.report.recipients as mod2

    for mod_file in (Path(mod.__file__), Path(mod2.__file__)):
        found = _imported_names(mod_file)
        hit = found & _FORBIDDEN_IMPORTS
        assert not hit, f"{mod_file} imports forbidden module(s): {hit}"
