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

    All fields are honest assessments. ``uses_canary_fallback`` is True
    on the macOS / Windows backends when the seeder is configured to
    embed canary URLs (operator set ZEE_CANARY_BASE_URL). It stays
    False on Linux because inotify observes reads directly, and on
    macOS / Windows when no base URL is configured.
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
