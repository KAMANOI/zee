"""macOS watcher backend — kqueue / EVFILT_VNODE (spec §9).

kqueue observes file-level change events (write, delete, attrib, rename,
extend). It does NOT observe reads. For read signals on macOS, Zee
relies on canary URLs embedded in decoys (see decoy/canary_token.py)
which fire out-of-band when an attacker dereferences them.

This honest split — change events here, read events via canary — is
reflected in the capability declaration.
"""

from __future__ import annotations

import logging
import os
import select
import sys
import threading
from pathlib import Path
from typing import Iterable, Optional

from ..errors import ZeeError, Z301_WATCHER_BACKEND_UNAVAILABLE, Z302_DECOY_PATH_NOT_FOUND
from ..events import TrapEvent
from .base import Capability, OnEvent

logger = logging.getLogger(__name__)


class MacOSKqueueWatcher:
    """kqueue/EVFILT_VNODE-based watcher. Change detection only."""

    def __init__(self) -> None:
        if sys.platform != "darwin":
            raise ZeeError(
                Z301_WATCHER_BACKEND_UNAVAILABLE,
                f"MacOSKqueueWatcher requires darwin; got {sys.platform}",
            )
        if not hasattr(select, "kqueue"):
            raise ZeeError(
                Z301_WATCHER_BACKEND_UNAVAILABLE,
                "select.kqueue not available in this Python build",
            )
        self._kq: Optional[select.kqueue] = None
        self._fds: dict[int, str] = {}
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def capability(self) -> Capability:
        return Capability(
            backend_name="macos_kqueue",
            detects_open=False,
            detects_read=False,
            detects_modify=True,
            uses_canary_fallback=True,
            notes=(
                "kqueue/EVFILT_VNODE for change detection only. Read detection "
                "is delegated to canary URLs embedded in decoys."
            ),
        )

    def start(
        self,
        decoy_paths: Iterable[str],
        asset_id: str,
        on_event: OnEvent,
    ) -> None:
        self._kq = select.kqueue()
        self._stop_event.clear()

        try:
            for raw in decoy_paths:
                p = Path(raw).expanduser().resolve()
                if not p.exists():
                    raise ZeeError(Z302_DECOY_PATH_NOT_FOUND, str(p))
                fd = os.open(str(p), os.O_RDONLY)
                self._fds[fd] = str(p)

            kevents = [
                select.kevent(
                    fd,
                    filter=select.KQ_FILTER_VNODE,
                    flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_CLEAR,
                    fflags=(
                        select.KQ_NOTE_WRITE
                        | select.KQ_NOTE_DELETE
                        | select.KQ_NOTE_ATTRIB
                        | select.KQ_NOTE_EXTEND
                        | select.KQ_NOTE_RENAME
                    ),
                )
                for fd in self._fds
            ]
            self._kq.control(kevents, 0, 0)

            self._thread = threading.Thread(
                target=self._loop,
                args=(asset_id, on_event),
                name="zee-macos-watcher",
                daemon=True,
            )
            self._thread.start()
        except Exception:
            # Clean up any FDs / kqueue opened before the failure point.
            self._cleanup_resources()
            raise

    def _cleanup_resources(self) -> None:
        for fd in list(self._fds):
            try:
                os.close(fd)
            except OSError:
                pass
        self._fds.clear()
        if self._kq is not None:
            try:
                self._kq.close()
            except OSError:
                pass
            self._kq = None

    def _loop(self, asset_id: str, on_event: OnEvent) -> None:
        while not self._stop_event.is_set():
            try:
                events = self._kq.control(None, 16, 0.5)
            except (OSError, ValueError):
                break
            for ev in events:
                path = self._fds.get(ev.ident)
                if path is None:
                    continue
                detail = _describe_fflags(ev.fflags)
                trap = TrapEvent.make(
                    source="decoy_touch",
                    confidence="high",
                    asset_id=asset_id,
                    decoy_path=path,
                    detail=detail,
                )
                try:
                    on_event(trap)
                except Exception:
                    logger.exception("on_event callback raised")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        self._cleanup_resources()


def _describe_fflags(fflags: int) -> str:
    parts: list[str] = []
    if fflags & select.KQ_NOTE_WRITE:
        parts.append("write")
    if fflags & select.KQ_NOTE_DELETE:
        parts.append("delete")
    if fflags & select.KQ_NOTE_ATTRIB:
        parts.append("attrib")
    if fflags & select.KQ_NOTE_EXTEND:
        parts.append("extend")
    if fflags & select.KQ_NOTE_RENAME:
        parts.append("rename")
    return "decoy " + ("+".join(parts) if parts else f"fflags=0x{fflags:x}")
