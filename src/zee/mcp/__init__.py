"""Zee MCP layer — optional, opt-in, read-only + propose-only.

This package exposes Zee's defensive *signals* (events, status, active
containment, policy) over the Model Context Protocol so that an agent
such as Claude Code can read what Zee is seeing and *propose* next
steps for an operator who has no dedicated security staff.

Hard boundaries (see spec_zee_mcp.md):

* It is an **optional extra** — `pip install zee[mcp]`. Zee core has
  zero dependencies and keeps working without this package installed.
* It **never** modifies Zee's containment logic. It only *reads* the
  event store and *returns proposals*. No write/cut/restore is ever
  executed from here.
* It **never** reaches the HMAC restore secret. `propose_restore`
  returns a plan plus the command a human must run; the human supplies
  the secret.
* Defaults are safe: ``enabled=false``, ``expose_actions=false``,
  ``redact_paths=true``. Everything is explicit opt-in.

The heavy import (`mcp` SDK) lives in :mod:`zee.mcp.server`, imported
lazily by the CLI so that `zee` keeps running on an install without the
extra.
"""

from __future__ import annotations

__all__ = ["McpConfig", "AuditLog", "EventReader"]

from .config import McpConfig
from .audit import AuditLog
from .reader import EventReader
