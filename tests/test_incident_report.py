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
    build_incident_report,
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
    # lane; the reference footer always lists both.
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


def _export_dict(tmp_path: Path, monkeypatch) -> dict:
    return json.loads(_make_export(tmp_path, monkeypatch).read_text(encoding="utf-8"))


def _write_json(tmp_path: Path, name: str, data: dict) -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return p


@pytest.mark.parametrize("mutate", [
    lambda d: d.pop("events_total"),
    lambda d: d.update(events_total=True),
    lambda d: d.update(events_total="1"),
    lambda d: d.update(events_included=-1),
    lambda d: d.pop("events"),
    lambda d: d.update(events={"a": 1}),
    lambda d: d.update(events=["not-an-object"]),
    lambda d: d.update(active_containments=None),
    lambda d: d.update(chain_verification=[]),
    lambda d: d["chain_verification"].pop("events_jsonl"),
    lambda d: d.update(schema_version=1),
    lambda d: d.pop("redacted"),
    lambda d: d.pop("events_truncated"),
    lambda d: d["report_fields"].update(affected_asset_ids="t-host"),
    lambda d: d["report_fields"].update(affected_asset_ids=[1]),
    lambda d: d["report_fields"].pop("affected_asset_ids"),
    lambda d: d["report_fields"].pop("incident_summary_auto"),
    lambda d: d["report_fields"].pop("detected_at_first"),
])
def test_broken_export_rejected_not_defaulted(tmp_path: Path, monkeypatch, mutate):
    data = _export_dict(tmp_path, monkeypatch)
    mutate(data)
    bad = _write_json(tmp_path, "broken.json", data)
    with pytest.raises(ZeeError) as e:
        load_export(bad)
    assert e.value.code == "Z1004"


def test_cli_broken_export_exits_with_z1004(tmp_path: Path, monkeypatch, capsys):
    data = _export_dict(tmp_path, monkeypatch)
    del data["events_total"]
    bad = _write_json(tmp_path, "broken.json", data)
    rc = main(["incident-report", "--export-json", str(bad), "--recipient", "ppc",
               "--out", str(tmp_path / "incident")])
    assert rc != 0
    assert "Z1004" in capsys.readouterr().err
    assert not (tmp_path / "incident.txt").exists()


def test_newline_in_export_cannot_forge_a_heading(tmp_path: Path, monkeypatch):
    data = _export_dict(tmp_path, monkeypatch)
    data["report_fields"]["incident_summary_auto"] = "ok\n## 偽見出し\r\x1b[31m\u0085x"
    data["report_fields"]["affected_asset_ids"] = ["a\n## 偽資産"]
    doc = build_incident_report(
        export=load_export(_write_json(tmp_path, "inj.json", data)),
        recipient="ppc", incident_label="L\n## 偽ラベル",
    )
    text = render_text(doc)
    for line in text.splitlines():
        assert not line.startswith("## 偽")
    assert "ok\\n## 偽見出し\\r\\u001b[31m\\u0085x" in text
    assert "a\\n## 偽資産" in text and "L\\n## 偽ラベル" in text
    assert "\x1b" not in text and "\x85" not in text
    assert "## 偽" not in render_html(doc).replace("\\n## 偽", "")


def test_unknown_event_fields_are_not_carried_over(tmp_path: Path, monkeypatch):
    data = _export_dict(tmp_path, monkeypatch)
    data["events"][0]["home_dir"] = "/Users/someone"
    data["events"][0]["api_key"] = "sk-SECRET-should-not-appear"
    data["active_containments"] = [{"asset_id": "t-host", "method": "full", "cut_at": "x",
                                    "platform": "darwin", "modified": ["en0"], "token": "SECRET2"}]
    doc = build_incident_report(export=load_export(_write_json(tmp_path, "extra.json", data)),
                                recipient="police")
    blob = json.dumps(doc, ensure_ascii=False) + render_text(doc)
    for leaked in ("home_dir", "/Users/someone", "api_key", "sk-SECRET", "SECRET2"):
        assert leaked not in blob
    assert doc["containment_export"]["events"][0]["asset_id"] == "t-host"
    assert doc["containment_export"]["active_containments"][0]["modified"] == ["en0"]


def test_unredacted_export_is_flagged(tmp_path: Path, monkeypatch, capsys):
    data = _export_dict(tmp_path, monkeypatch)
    redacted_doc = build_incident_report(export=load_export(_write_json(tmp_path, "r.json", data)),
                                         recipient="police")
    assert redacted_doc["containment_export"]["redacted"] is True
    assert "--no-redact" not in render_text(redacted_doc)

    data["redacted"] = False
    raw = _write_json(tmp_path, "raw.json", data)
    rc = main(["incident-report", "--export-json", str(raw), "--recipient", "police",
               "--out", str(tmp_path / "incident")])
    assert rc == 0
    assert "--no-redact" in capsys.readouterr().err
    assert "--no-redact" in (tmp_path / "incident.txt").read_text(encoding="utf-8")
    assert "--no-redact" in (tmp_path / "incident.html").read_text(encoding="utf-8")
    assert json.loads((tmp_path / "incident.json").read_text(encoding="utf-8"))["containment_export"]["redacted"] is False


def test_ppc_cause_mentions_only_decoy_events(tmp_path: Path, monkeypatch):
    doc = build_incident_report(export=load_export(_make_export(tmp_path, monkeypatch)), recipient="ppc")
    cause = doc["ppc_statutory_items"]["4 原因"]
    assert "囮の検知イベント" in cause and "カナリア" not in cause
    text = render_text(doc)
    assert "カナリア" not in text and "ダミー" not in text


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
