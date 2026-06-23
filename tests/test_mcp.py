"""Tests for the optional MCP layer (zee.mcp).

Skipped automatically when the `mcp` extra is not installed, so the
core CI (which has zero dependencies) is unaffected.

Invariants asserted (spec_zee_mcp.md §5, §9):
  * read tools / resources never mutate the event store
  * redact_paths defaults to true and masks the free-text detail
  * propose_* tools never execute and never surface the restore secret
  * every MCP access is appended to the audit log with source="mcp"
  * config defaults are the safe ones
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("mcp")

from zee.mcp.audit import AuditLog  # noqa: E402
from zee.mcp.config import McpConfig  # noqa: E402
from zee.mcp.reader import EventReader  # noqa: E402
from zee.mcp.server import build_server  # noqa: E402


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _write_event(d, **over):
    rec = {
        "type": "trap_event",
        "source": "decoy_touch",
        "confidence": "high",
        "asset_id": "client-files",
        "decoy_ref": "client-files#0",
        "detected_at": datetime.now(timezone.utc).isoformat(),
        "detail": "/Users/secret/customer.xlsx modified",
        "op_class": "change",
    }
    rec.update(over)
    p = d / "events.jsonl"
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")
    return rec


def _call(mcp, name, args=None):
    _content, structured = asyncio.run(mcp.call_tool(name, args or {}))
    return structured.get("result", structured)


def _read(mcp, uri):
    res = asyncio.run(mcp.read_resource(uri))
    return json.loads(list(res)[0].content)


def _audit_lines(d):
    p = d / "mcp_audit.jsonl"
    if not p.exists():
        return []
    return [json.loads(x) for x in p.read_text().splitlines() if x.strip()]


# --------------------------------------------------------------------------
# config
# --------------------------------------------------------------------------

def test_config_defaults_are_safe():
    c = McpConfig()
    assert c.enabled is False
    assert c.expose_actions is False
    assert c.redact_paths is True
    assert c.transport == "stdio"
    assert c.audit is True


def test_config_load_reads_mcp_table(tmp_path):
    toml = tmp_path / "assets.toml"
    toml.write_text(
        "[mcp]\nenabled = true\nredact_paths = false\nexpose_actions = true\n"
    )
    c = McpConfig.load(toml)
    assert c.enabled is True
    assert c.redact_paths is False
    assert c.expose_actions is True


def test_config_load_malformed_falls_back_to_safe(tmp_path):
    toml = tmp_path / "assets.toml"
    toml.write_text("this is not = valid toml [[[")
    c = McpConfig.load(toml)
    assert c.enabled is False
    assert c.redact_paths is True


def test_config_missing_file_is_safe(tmp_path):
    c = McpConfig.load(tmp_path / "nope.toml")
    assert c.enabled is False and c.redact_paths is True


# --------------------------------------------------------------------------
# reader
# --------------------------------------------------------------------------

def test_redact_default_masks_detail(tmp_path):
    _write_event(tmp_path)
    r = EventReader(log_dir=tmp_path)  # default redact_paths=True
    ev = r.recent_events()[0]
    assert ev["detail"] == "[redacted]"
    assert "customer.xlsx" not in json.dumps(ev)


def test_no_redact_reveals_detail(tmp_path):
    _write_event(tmp_path)
    r = EventReader(log_dir=tmp_path, redact_paths=False)
    ev = r.recent_events()[0]
    assert "customer.xlsx" in ev["detail"]


def test_query_events_filters(tmp_path):
    _write_event(tmp_path, op_class="change", confidence="high")
    _write_event(
        tmp_path, source="manual", op_class="read", confidence="low",
        detail="read touch",
    )
    r = EventReader(log_dir=tmp_path, redact_paths=False)
    assert len(r.query_events()) == 2
    assert all(e["op_class"] == "change" for e in r.query_events(op_class="change"))
    assert all(e["confidence"] == "low" for e in r.query_events(confidence="low"))
    assert len(r.query_events(limit=1)) == 1


def test_get_event_roundtrip(tmp_path):
    _write_event(tmp_path)
    r = EventReader(log_dir=tmp_path)
    eid = r.recent_events()[0]["event_id"]
    assert r.get_event(eid) is not None
    assert r.get_event("deadbeef0000") is None


def test_skips_malformed_lines(tmp_path):
    _write_event(tmp_path)
    with (tmp_path / "events.jsonl").open("a") as f:
        f.write("{partial broken line\n")
    r = EventReader(log_dir=tmp_path)
    assert len(r.recent_events()) == 1  # broken line ignored, valid kept


def test_health_check_shape(tmp_path):
    r = EventReader(log_dir=tmp_path)
    h = r.health_check()
    assert h["event_store_reachable"] is False
    assert "watcher_liveness" in h


# --------------------------------------------------------------------------
# server: non-mutation, audit, redaction end-to-end
# --------------------------------------------------------------------------

def test_read_tools_do_not_mutate_event_store(tmp_path):
    _write_event(tmp_path)
    before = (tmp_path / "events.jsonl").read_bytes()
    mcp = build_server(config=McpConfig(), log_dir=tmp_path, config_path=None)
    _call(mcp, "query_events", {})
    _call(mcp, "summarize_incident", {})
    _read(mcp, "zee://status")
    _read(mcp, "zee://events/recent")
    after = (tmp_path / "events.jsonl").read_bytes()
    assert before == after


def test_every_access_is_audited(tmp_path):
    _write_event(tmp_path)
    mcp = build_server(config=McpConfig(), log_dir=tmp_path, config_path=None)
    _call(mcp, "query_events", {})
    _read(mcp, "zee://status")
    _call(mcp, "propose_release", {"asset_id": "client-files"})
    lines = _audit_lines(tmp_path)
    assert len(lines) >= 3
    assert all(l["source"] == "mcp" for l in lines)
    actions = {l["action"] for l in lines}
    assert "tool:query_events" in actions
    assert "resource:zee://status" in actions
    assert "tool:propose_release" in actions


def test_server_redacts_by_default(tmp_path):
    _write_event(tmp_path)
    mcp = build_server(config=McpConfig(), log_dir=tmp_path, config_path=None)
    evs = _call(mcp, "query_events", {})
    assert evs[0]["detail"] == "[redacted]"


# --------------------------------------------------------------------------
# propose tools: never execute, never surface the secret
# --------------------------------------------------------------------------

def test_propose_release_does_not_execute(tmp_path):
    mcp = build_server(config=McpConfig(), log_dir=tmp_path, config_path=None)
    out = _call(mcp, "propose_release", {"asset_id": "client-files"})
    assert out["executed"] is False
    assert "zee restore client-files" in out["command_for_human"]


def test_propose_restore_never_surfaces_a_real_secret(tmp_path):
    mcp = build_server(config=McpConfig(), log_dir=tmp_path, config_path=None)
    out = _call(mcp, "propose_restore", {"asset_id": "client-files"})
    blob = json.dumps(out)
    assert out["executed"] is False
    # only the placeholder is present, never a concrete token value
    assert "<YOUR_RESTORE_TOKEN>" in blob


def test_propose_tools_make_no_files_beyond_audit(tmp_path):
    mcp = build_server(config=McpConfig(), log_dir=tmp_path, config_path=None)
    _call(mcp, "propose_release", {"asset_id": "a"})
    _call(mcp, "propose_restore", {"asset_id": "a"})
    _call(mcp, "propose_policy_change", {"rule_description": "x"})
    # no events.jsonl / cut_state.jsonl created by proposing
    assert not (tmp_path / "events.jsonl").exists()
    assert not (tmp_path / "cut_state.jsonl").exists()


# --------------------------------------------------------------------------
# audit can be disabled
# --------------------------------------------------------------------------

def test_audit_can_be_disabled(tmp_path):
    a = AuditLog(log_dir=tmp_path, enabled=False)
    a.record("tool:query_events")
    assert not (tmp_path / "mcp_audit.jsonl").exists()


# --------------------------------------------------------------------------
# tool registration / read-only hints
# --------------------------------------------------------------------------

def test_query_events_timezone_aware_filtering(tmp_path):
    # 09:00+09:00 == 00:00Z (out of range); 05:00+00:00 == 05:00Z (in range)
    _write_event(
        tmp_path, detected_at="2026-06-23T09:00:00+09:00", detail="early",
        op_class="change",
    )
    _write_event(
        tmp_path, detected_at="2026-06-23T05:00:00+00:00", detail="late",
        op_class="change",
    )
    r = EventReader(log_dir=tmp_path, redact_paths=False)
    got = [e["detail"] for e in r.query_events(since="2026-06-23T01:00:00+00:00")]
    assert "late" in got and "early" not in got  # tz-correct, not string-order
    # newest-first by real instant: 05:00Z is later than 00:00Z
    assert r.query_events()[0]["detail"] == "late"


def test_audit_redacts_freetext_and_paths(tmp_path):
    a = AuditLog(log_dir=tmp_path, enabled=True, redact=True)
    a.record(
        "tool:propose_policy_change",
        {"rule_description": "block /Users/secret/tax.xlsx", "asset_id": "cf"},
    )
    a.record("tool:get_event", {"event_id": "abc123"})
    lines = _audit_lines(tmp_path)
    assert lines[0]["params"]["rule_description"] == "[redacted]"
    assert lines[0]["params"]["asset_id"] == "cf"  # identifier kept usable
    assert "tax.xlsx" not in json.dumps(lines)
    assert lines[1]["params"]["event_id"] == "abc123"  # hash kept visible


def test_audit_no_redact_keeps_params(tmp_path):
    a = AuditLog(log_dir=tmp_path, enabled=True, redact=False)
    a.record("x", {"justification": "/p/q.xlsx"})
    assert _audit_lines(tmp_path)[0]["params"]["justification"] == "/p/q.xlsx"


def test_server_redacts_audit_params_by_default(tmp_path):
    mcp = build_server(config=McpConfig(), log_dir=tmp_path, config_path=None)
    _call(mcp, "propose_policy_change",
          {"rule_description": "block /Users/secret/tax.xlsx"})
    assert "tax.xlsx" not in (tmp_path / "mcp_audit.jsonl").read_text()


def test_read_tools_have_readonly_hint(tmp_path):
    mcp = build_server(config=McpConfig(), log_dir=tmp_path, config_path=None)
    tools = {t.name: t for t in asyncio.run(mcp.list_tools())}
    assert getattr(tools["query_events"].annotations, "readOnlyHint", None) is True
    assert getattr(tools["health_check"].annotations, "readOnlyHint", None) is True
    # propose tools are present
    assert "propose_release" in tools
    assert "propose_restore" in tools
