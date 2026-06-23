"""[mcp] configuration block — lives alongside the existing policy TOML.

All defaults are the safe ones (spec §8): the MCP layer is disabled,
exposes proposals only, and redacts paths. A missing or malformed file
yields the default (safe) config rather than an error, so a typo never
silently turns *off* a protection that was supposed to be on.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class McpConfig:
    enabled: bool = False
    transport: str = "stdio"
    expose_actions: bool = False
    redact_paths: bool = True
    event_store_path: Optional[str] = None
    audit: bool = True

    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> "McpConfig":
        """Read the ``[mcp]`` table from a TOML file, falling back to
        the safe defaults if the file or table is absent/malformed."""
        if config_path is None:
            return cls()
        p = Path(config_path)
        if not p.exists():
            return cls()
        try:
            with p.open("rb") as f:
                data = tomllib.load(f)
        except (OSError, tomllib.TOMLDecodeError):
            return cls()
        mcp = data.get("mcp", {})
        if not isinstance(mcp, dict):
            return cls()
        return cls(
            enabled=bool(mcp.get("enabled", False)),
            transport=str(mcp.get("transport", "stdio")),
            expose_actions=bool(mcp.get("expose_actions", False)),
            redact_paths=bool(mcp.get("redact_paths", True)),
            event_store_path=(mcp.get("event_store_path") or None),
            audit=bool(mcp.get("audit", True)),
        )
