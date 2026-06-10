"""macOS watcher backend — kqueue / EVFILT_VNODE (spec §9).

kqueue observes file-level change events (write, delete, attrib, rename,
extend). It does NOT observe reads. Read detection on macOS is wired
via canary URLs embedded in decoys (the CanaryTokenRegistry in
decoy/canary_token.py), which fire out-of-band at an operator-controlled
external endpoint when an attacker dereferences them.

The watcher itself does not handle the canary path — the decoy seeder
embeds the URL, and an external endpoint receives the dereference.
``canary_configured`` is passed in only so the ``capability()`` output
honestly reflects whether the operator has wired ZEE_CANARY_BASE_URL.

This honest split — change events here, read detection out-of-band —
is reflected in the capability declaration.
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

    def __init__(self, *, canary_configured: bool = False) -> None:
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
        # fd -> "asset_id#index" for the v0.3 decoy_ref payload.
        self._fd_to_ref: dict[int, str] = {}
        # path -> ref, kept for re-registration after delete/rename.
        self._path_to_ref: dict[str, str] = {}
        # paths queued for re-registration (the decoy was deleted or renamed).
        self._pending_rewatch: set[str] = set()
        self._pending_lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._canary_configured = canary_configured

    def capability(self) -> Capability:
        if self._canary_configured:
            notes = (
                "kqueue/EVFILT_VNODE for change detection. Read detection "
                "is delegated to canary URLs embedded in decoys by the "
                "seeder; the operator's external endpoint fires when an "
                "attacker dereferences a decoy URL (out-of-band — never "
                "re-enters Zee's local responder)."
            )
        else:
            notes = (
                "kqueue/EVFILT_VNODE for change detection. Set "
                "ZEE_CANARY_BASE_URL to wire the canary URL path; "
                "without it, read-only attacker activity against a "
                "macOS decoy is not observed."
            )
        return Capability(
            backend_name="macos_kqueue",
            detects_open=False,
            detects_read=False,
            detects_modify=True,
            uses_canary_fallback=self._canary_configured,
            notes=notes,
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
            for index, raw in enumerate(decoy_paths):
                p = Path(raw).expanduser().resolve()
                if not p.exists():
                    raise ZeeError(Z302_DECOY_PATH_NOT_FOUND, str(p))
                fd = os.open(str(p), os.O_RDONLY)
                ref = f"{asset_id}#{index}"
                self._fds[fd] = str(p)
                self._fd_to_ref[fd] = ref
                self._path_to_ref[str(p)] = ref

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
        self._fd_to_ref.clear()
        with self._pending_lock:
            self._pending_rewatch.clear()
        if self._kq is not None:
            try:
                self._kq.close()
            except OSError:
                pass
            self._kq = None

    def _try_reregister(self, path: str) -> bool:
        """Open and re-register a decoy that was deleted or renamed.

        Returns True when registration succeeds so the caller can remove
        the path from the pending set.  Called from _loop only.
        """
        try:
            if self._kq is None:
                return False
            p = Path(path)
            if not p.exists():
                return False
            fd = os.open(str(p), os.O_RDONLY)
            ref = self._path_to_ref.get(path, f"?#?")
            self._fds[fd] = path
            self._fd_to_ref[fd] = ref
            kevent = select.kevent(
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
            self._kq.control([kevent], 0, 0)
            return True
        except OSError:
            return False

    def _loop(self, asset_id: str, on_event: OnEvent) -> None:
        while not self._stop_event.is_set():
            # Retry re-registration for any decoys deleted/renamed since the
            # last iteration.
            with self._pending_lock:
                pending = list(self._pending_rewatch)
            for path in pending:
                if self._try_reregister(path):
                    with self._pending_lock:
                        self._pending_rewatch.discard(path)

            try:
                events = self._kq.control(None, 16, 0.5)
            except (OSError, ValueError):
                break
            for ev in events:
                path = self._fds.get(ev.ident)
                if path is None:
                    continue
                detail = _describe_fflags(ev.fflags)
                op_class = _classify_fflags(ev.fflags)
                trap = TrapEvent.make(
                    source="decoy_touch",
                    confidence="high",
                    asset_id=asset_id,
                    decoy_path=path,
                    detail=detail,
                    op_class=op_class,
                    decoy_ref=self._fd_to_ref.get(ev.ident),
                )
                try:
                    on_event(trap)
                except Exception:
                    logger.exception("on_event callback raised")

                # Queue for re-registration when the decoy is deleted or renamed.
                if ev.fflags & (select.KQ_NOTE_DELETE | select.KQ_NOTE_RENAME):
                    with self._pending_lock:
                        self._pending_rewatch.add(path)
                    # Deregister the stale vnode so kqueue stops sending events.
                    try:
                        cancel = select.kevent(
                            ev.ident,
                            filter=select.KQ_FILTER_VNODE,
                            flags=select.KQ_EV_DELETE,
                        )
                        self._kq.control([cancel], 0, 0)
                    except OSError:
                        pass
                    try:
                        os.close(ev.ident)
                    except OSError:
                        pass
                    self._fds.pop(ev.ident, None)
                    self._fd_to_ref.pop(ev.ident, None)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        self._cleanup_resources()


def _classify_fflags(fflags: int) -> str:
    """Map a kqueue VNODE fflags bitset to read/change.

    Change-like: WRITE, DELETE, EXTEND, RENAME.
    Read-like (default): ATTRIB — attribute reads can be triggered by
    AV/Spotlight inspection, so we put ATTRIB on the read side to
    avoid spurious auto-cuts. The decision is reported here so the
    operator can revisit it.
    """
    change_mask = (
        select.KQ_NOTE_WRITE
        | select.KQ_NOTE_DELETE
        | select.KQ_NOTE_EXTEND
        | select.KQ_NOTE_RENAME
    )
    if fflags & change_mask:
        return "change"
    return "read"


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
