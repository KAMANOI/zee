"""Audit trail for every MCP access.

Each read *and* each proposal is appended to ``mcp_audit.jsonl`` in the
same state directory as ``events.jsonl`` with ``source="mcp"``. This is
the compliance / audit-trail story for SMEs: which agent looked at what,
and what it proposed. Auditing must never break the read path, so all
errors are swallowed.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from ..telemetry.events_log import default_log_dir

# Free-text tool arguments that may carry customer file names or paths.
# When redacting, these are masked entirely; short identifiers
# (asset_id, op_class, limit, event_id-hash, since/until) stay visible
# so the audit trail is still useful.
_FREE_TEXT_KEYS = frozenset(
    {"justification", "rule_description", "point_in_time", "detail"}
)


def _redact_params(
    params: dict[str, Any], redact: bool
) -> dict[str, Any]:
    if not redact or not params:
        return params
    out: dict[str, Any] = {}
    for k, v in params.items():
        if k in _FREE_TEXT_KEYS:
            out[k] = "[redacted]" if v else v
        elif isinstance(v, str) and ("/" in v or "\\" in v):
            out[k] = "[redacted]"
        else:
            out[k] = v
    return out


class AuditLog:
    def __init__(
        self,
        log_dir: Optional[Path] = None,
        enabled: bool = True,
        redact: bool = True,
    ) -> None:
        self.enabled = enabled
        self.redact = redact
        self.log_dir = Path(log_dir) if log_dir else default_log_dir()
        self.path = self.log_dir / "mcp_audit.jsonl"

    def record(self, action: str, params: Optional[dict[str, Any]] = None) -> None:
        if not self.enabled:
            return
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(self.log_dir, 0o700)
            except (OSError, NotImplementedError):
                pass
            rec = {
                "type": "mcp_audit",
                "recorded_at": datetime.now(timezone.utc).isoformat(),
                "source": "mcp",
                "action": action,
                "params": _redact_params(params or {}, self.redact),
            }
            existed = self.path.exists()
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            if not existed:
                try:
                    os.chmod(self.path, 0o600)
                except (OSError, NotImplementedError):
                    pass
        except OSError:
            # Auditing is best-effort; it must never break the read path.
            pass
