"""Shared Watcher interface and capability declaration (spec §9).

Each OS backend declares what it can and cannot do. The capability matrix
is rendered in `zee capability` and in the README — no backend should
silently overstate its abilities.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, Protocol

from ..events import TrapEvent

OnEvent = Callable[[TrapEvent], None]


@dataclass(frozen=True)
class Capability:
    """What this watcher backend can detect on the current OS.

    All fields are honest assessments. If a backend has no kernel-level
    read hook (kqueue, ReadDirectoryChangesW), it should set
    detects_read=False. The canary path is planned for read detection on
    those backends but is NOT wired in v0.1 — see decoy/canary_token.py
    and the v0.1 Limitations in README.
    """

    backend_name: str
    detects_open: bool
    detects_read: bool
    detects_modify: bool
    uses_canary_fallback: bool
    notes: str = ""


class Watcher(Protocol):
    """OS-specific watcher implementations must satisfy this protocol."""

    def capability(self) -> Capability:
        ...

    def start(self, decoy_paths: Iterable[str], asset_id: str, on_event: OnEvent) -> None:
        ...

    def stop(self) -> None:
        ...
