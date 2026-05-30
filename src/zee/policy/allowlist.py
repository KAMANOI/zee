"""Allowlist of legitimate processes that must never be ensnared.

Backup tools, antivirus scanners, indexing daemons, and admin operators
sometimes touch decoy files in the course of legitimate work. The
allowlist exempts them from triggering containment.

Standard library only. Identification is by absolute executable path
(harder to spoof) or by process name (used only as a fallback hint).
Source can be a JSON file or in-memory additions. The JSON file's
permissions are checked: if it is group- or world-writable, the file is
refused — otherwise an attacker could add themselves to the allowlist.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import stat
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class Allowlist:
    """Allowlist of legitimate identifiers that bypass containment."""

    def __init__(
        self,
        *,
        process_names: Optional[set[str]] = None,
        exe_paths: Optional[set[str]] = None,
        ip_cidrs: Optional[list[str]] = None,
    ) -> None:
        self._process_names: set[str] = set(process_names or set())
        self._exe_paths: set[str] = set(exe_paths or set())
        self._networks: list = []
        for cidr in (ip_cidrs or []):
            self._add_network(cidr)

    # ── construction ───────────────────────────────────────────────

    @classmethod
    def from_file(cls, path: Optional[str | Path] = None) -> "Allowlist":
        """Load an allowlist from JSON. Returns empty when the file is missing.

        Refuses files (or parent dirs) that are group- or world-writable.
        """
        if path is None:
            env = os.environ.get("ZEE_ALLOWLIST_PATH", "")
            if not env:
                return cls()
            path = env
        p = Path(path)
        if not p.exists():
            logger.info("allowlist file not present: %s", p)
            return cls()

        if not cls._is_path_secure(p):
            logger.error(
                "allowlist file %s has loose permissions; refusing to load. "
                "chmod 600 to make it owner-only.",
                p,
            )
            return cls()

        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            logger.error("allowlist load failed (%s); continuing with empty list", e)
            return cls()

        return cls(
            process_names=set(data.get("process_names", [])),
            exe_paths=set(data.get("exe_paths", [])),
            ip_cidrs=list(data.get("ip_cidrs", [])),
        )

    @staticmethod
    def _is_path_secure(path: Path) -> bool:
        try:
            for target in (path, path.parent):
                mode = os.stat(target).st_mode
                if mode & (stat.S_IWGRP | stat.S_IWOTH):
                    return False
        except OSError:
            return False
        return True

    def add_process(self, name: str) -> None:
        self._process_names.add(name)

    def add_exe_path(self, exe_path: str) -> None:
        """Add a legitimate tool by absolute exe path (harder to spoof)."""
        self._exe_paths.add(exe_path)

    def add_ip_cidr(self, cidr: str) -> None:
        self._add_network(cidr)

    # ── lookup ─────────────────────────────────────────────────────

    def is_protected(
        self,
        *,
        proc_name: Optional[str] = None,
        exe_path: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> bool:
        """True when any one identifier matches the allowlist.

        Prefer exe_path when available; it is harder to spoof than a
        process name.
        """
        if exe_path and exe_path in self._exe_paths:
            return True
        if proc_name and proc_name in self._process_names:
            return True
        if ip:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                return False
            return any(addr in net for net in self._networks)
        return False

    # ── internal ───────────────────────────────────────────────────

    def _add_network(self, cidr: str) -> None:
        try:
            self._networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            logger.error("ignoring invalid CIDR: %s", cidr)
