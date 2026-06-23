"""FastMCP server assembly for Zee (read-only + propose-only).

Importing this module requires the optional ``mcp`` dependency
(``pip install zee[mcp]``). The CLI imports it lazily and prints a
friendly hint if the extra is missing.

Process model: this server is meant to be launched as a subprocess by
the MCP client over stdio. It opens the event store read-only and runs
in a process that does **not** hold the HMAC restore secret. Nothing
here cuts, restores, or edits policy — propose_* tools return a plan and
the command a human must run.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from .audit import AuditLog
from .config import McpConfig
from .reader import EventReader

_INSTRUCTIONS = (
    "Read-only and propose-only view of a local Zee deployment. "
    "Resources and query_* tools never modify anything. propose_* tools "
    "return a plan plus the exact command a human operator must run; they "
    "never execute, and the MCP layer never holds Zee's restore secret. "
    "Paths may be redacted depending on configuration."
)


def build_server(
    config: Optional[McpConfig] = None,
    log_dir: Optional[Path] = None,
    config_path: Optional[str | Path] = "assets.toml",
) -> FastMCP:
    cfg = config or McpConfig()
    reader = EventReader(log_dir=log_dir, redact_paths=cfg.redact_paths)
    audit = AuditLog(log_dir=log_dir, enabled=cfg.audit, redact=cfg.redact_paths)
    mcp: FastMCP = FastMCP("zee", instructions=_INSTRUCTIONS)

    def _json(obj: Any) -> str:
        return json.dumps(obj, ensure_ascii=False, indent=2)

    # ---- Resources (reference only) -------------------------------------

    @mcp.resource(
        "zee://status", name="Zee status", mime_type="application/json"
    )
    def status_resource() -> str:
        audit.record("resource:zee://status")
        return _json(reader.status_summary())

    @mcp.resource(
        "zee://events/recent",
        name="Zee recent events",
        mime_type="application/json",
    )
    def events_recent_resource() -> str:
        audit.record("resource:zee://events/recent")
        return _json(reader.recent_events(limit=50))

    @mcp.resource(
        "zee://containment/active",
        name="Zee active containment",
        mime_type="application/json",
    )
    def containment_active_resource() -> str:
        audit.record("resource:zee://containment/active")
        return _json(reader.active_containments())

    @mcp.resource(
        "zee://policy", name="Zee policy", mime_type="application/json"
    )
    def policy_resource() -> str:
        audit.record("resource:zee://policy")
        return _json(reader.policy_view(config_path))

    # ---- Read tools (readOnlyHint=true) ---------------------------------

    _RO = ToolAnnotations(readOnlyHint=True)

    @mcp.tool(annotations=_RO)
    def query_events(
        since: Optional[str] = None,
        until: Optional[str] = None,
        op_class: Optional[str] = None,
        confidence: Optional[str] = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Query trap events. Filters are ISO8601 timestamps (since/until),
        op_class ('read'|'change'), and confidence ('high'|'medium'|'low').
        Returns newest first."""
        audit.record(
            "tool:query_events",
            {
                "since": since,
                "until": until,
                "op_class": op_class,
                "confidence": confidence,
                "limit": limit,
            },
        )
        return reader.query_events(since, until, op_class, confidence, limit)

    @mcp.tool(annotations=_RO)
    def get_event(event_id: str) -> dict[str, Any]:
        """Fetch a single canonical event by its event_id."""
        audit.record("tool:get_event", {"event_id": event_id})
        ev = reader.get_event(event_id)
        return ev or {"error": "event not found", "event_id": event_id}

    @mcp.tool(annotations=_RO)
    def explain_containment(asset_id: str) -> dict[str, Any]:
        """Explain why an asset is contained: the active cut plus the
        recent change-class events for that asset."""
        audit.record("tool:explain_containment", {"asset_id": asset_id})
        active = [
            c for c in reader.active_containments() if c["asset_id"] == asset_id
        ]
        recent = [
            e
            for e in reader.query_events(op_class="change", limit=10)
            if e["asset_id"] == asset_id
        ]
        return {
            "asset_id": asset_id,
            "active_containment": active[0] if active else None,
            "recent_change_events": recent,
        }

    @mcp.tool(annotations=_RO)
    def summarize_incident(since: Optional[str] = None) -> dict[str, Any]:
        """Summarise burst activity and event totals into one overview."""
        audit.record("tool:summarize_incident", {"since": since})
        s = reader.status_summary()
        return {
            "since": since,
            "totals": s["totals"],
            "bursts": s["bursts"],
            "per_asset": s["per_asset"],
        }

    @mcp.tool(annotations=_RO)
    def get_policy() -> dict[str, Any]:
        """Return the current policy view (decoy paths redacted by default)."""
        audit.record("tool:get_policy")
        return reader.policy_view(config_path)

    @mcp.tool(annotations=_RO)
    def health_check() -> dict[str, Any]:
        """Report event-store reachability and redaction setting."""
        audit.record("tool:health_check")
        return reader.health_check()

    # ---- Propose tools (never execute in v0.6.0) ------------------------

    def _proposal_only() -> bool:
        # v0.6.0 ships propose-only regardless; expose_actions is reserved
        # for a future gated-execution version.
        return True

    @mcp.tool()
    def propose_release(asset_id: str, justification: str = "") -> dict[str, Any]:
        """Propose releasing containment for an asset. Returns the command
        a human must run; never executes and never holds the secret."""
        audit.record(
            "tool:propose_release",
            {"asset_id": asset_id, "justification": justification},
        )
        return {
            "proposal": "release_containment",
            "asset_id": asset_id,
            "justification": justification,
            "command_for_human": (
                f"zee restore {asset_id} --token <YOUR_RESTORE_TOKEN>"
            ),
            "note": (
                "Zee MCP never holds the restore token. A human runs this "
                "command and supplies the secret."
            ),
            "executed": False,
        }

    @mcp.tool()
    def propose_restore(
        asset_id: str, point_in_time: str = ""
    ) -> dict[str, Any]:
        """Propose a restore plan for an asset. Returns the steps and the
        signed command a human must run; never executes."""
        audit.record(
            "tool:propose_restore",
            {"asset_id": asset_id, "point_in_time": point_in_time},
        )
        return {
            "proposal": "restore",
            "asset_id": asset_id,
            "point_in_time": point_in_time or "latest",
            "plan": [
                "Operator reviews the active containment and recent events.",
                "Operator runs the command below with the restore token.",
                "Operator verifies `zee status` shows the cut cleared.",
            ],
            "command_for_human": (
                f"zee restore {asset_id} --token <YOUR_RESTORE_TOKEN>"
            ),
            "note": (
                "The HMAC restore secret is supplied by the human at run "
                "time and is never read or stored by the MCP layer."
            ),
            "executed": False,
        }

    @mcp.tool()
    def propose_policy_change(rule_description: str) -> dict[str, Any]:
        """Propose a policy (assets.toml) change as a reviewable suggestion.
        Returns suggested TOML; never edits the file."""
        audit.record(
            "tool:propose_policy_change", {"rule_description": rule_description}
        )
        return {
            "proposal": "policy_change",
            "rule_description": rule_description,
            "suggested_toml": (
                "# Review and apply by hand in assets.toml:\n"
                "# [[asset]]\n"
                '# id = "..."\n'
                '# decoy_paths = ["..."]\n'
                '# cut_method = "egress"  # or "full"\n'
            ),
            "note": "Suggestion only. Zee MCP never edits assets.toml.",
            "executed": False,
        }

    return mcp


def serve(
    config_path: str | Path = "assets.toml", log_dir: Optional[Path] = None
) -> None:
    """Build and run the server over stdio (local-only transport)."""
    cfg = McpConfig.load(Path(config_path))
    server = build_server(config=cfg, log_dir=log_dir, config_path=config_path)
    server.run(transport="stdio")
