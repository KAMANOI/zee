"""Linux watcher backend — inotify via ctypes (spec §9).

Detects read (IN_ACCESS) and open (IN_OPEN) on decoy files. Both are
treated as decoy_touch with confidence='high'. The backend uses the
standard library only (ctypes), so no extra dependency is needed.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import logging
import os
import struct
import sys
import threading
from pathlib import Path
from typing import Iterable

from ..errors import ZeeError, Z301_WATCHER_BACKEND_UNAVAILABLE, Z302_DECOY_PATH_NOT_FOUND
from ..events import TrapEvent
from .base import Capability, OnEvent

logger = logging.getLogger(__name__)

# inotify event flags (uapi/linux/inotify.h)
IN_ACCESS = 0x00000001
IN_MODIFY = 0x00000002
IN_OPEN = 0x00000020
IN_CLOSE_NOWRITE = 0x00000010
IN_CLOSE_WRITE = 0x00000008
IN_DELETE_SELF = 0x00000400  # watched file/dir itself was deleted
IN_MOVE_SELF = 0x00000800    # watched file/dir itself was moved
IN_IGNORED = 0x00008000      # watch removed by kernel (file gone)

# Mask used for decoy files: any read/open should trip the wire,
# AND any disappearance of the decoy itself must be surfaced
# (a silent zee with a broken decoy is worse than a noisy one).
DECOY_MASK = (
    IN_ACCESS | IN_OPEN | IN_MODIFY | IN_DELETE_SELF | IN_MOVE_SELF
)

# inotify_event header layout: int wd, uint32 mask, uint32 cookie, uint32 len
_EVENT_HEADER = struct.Struct("iIII")


class LinuxInotifyWatcher:
    """inotify-based watcher. Only works on Linux."""

    def __init__(self) -> None:
        if not sys.platform.startswith("linux"):
            raise ZeeError(
                Z301_WATCHER_BACKEND_UNAVAILABLE,
                f"LinuxInotifyWatcher requires linux; got {sys.platform}",
            )
        self._libc = self._load_libc()
        self._fd: int = -1
        self._wd_to_path: dict[int, str] = {}
        # path -> "asset_id#index" for the v0.3 decoy_ref payload.
        self._wd_to_ref: dict[int, str] = {}
        # path -> ref, kept for re-registration after delete/move.
        self._path_to_ref: dict[str, str] = {}
        # paths queued for re-registration.
        self._pending_rewatch: set[str] = set()
        self._pending_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    @staticmethod
    def _load_libc() -> ctypes.CDLL:
        name = ctypes.util.find_library("c")
        if not name:
            raise ZeeError(
                Z301_WATCHER_BACKEND_UNAVAILABLE,
                "libc not found via ctypes.util.find_library",
            )
        libc = ctypes.CDLL(name, use_errno=True)
        libc.inotify_init1.argtypes = [ctypes.c_int]
        libc.inotify_init1.restype = ctypes.c_int
        libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        libc.inotify_add_watch.restype = ctypes.c_int
        libc.inotify_rm_watch.argtypes = [ctypes.c_int, ctypes.c_int]
        libc.inotify_rm_watch.restype = ctypes.c_int
        return libc

    def capability(self) -> Capability:
        return Capability(
            backend_name="linux_inotify",
            detects_open=True,
            detects_read=True,
            detects_modify=True,
            uses_canary_fallback=False,
            notes="Direct kernel events via inotify (IN_ACCESS / IN_OPEN / IN_MODIFY).",
        )

    def start(
        self,
        decoy_paths: Iterable[str],
        asset_id: str,
        on_event: OnEvent,
    ) -> None:
        IN_NONBLOCK = 0o4000  # from <fcntl.h>
        fd = self._libc.inotify_init1(IN_NONBLOCK)
        if fd < 0:
            err = ctypes.get_errno()
            raise ZeeError(
                Z301_WATCHER_BACKEND_UNAVAILABLE,
                f"inotify_init1 failed: {os.strerror(err)}",
            )
        self._fd = fd
        self._stop_event.clear()

        for index, raw in enumerate(decoy_paths):
            p = Path(raw).expanduser().resolve()
            if not p.exists():
                raise ZeeError(Z302_DECOY_PATH_NOT_FOUND, str(p))
            wd = self._libc.inotify_add_watch(self._fd, str(p).encode(), DECOY_MASK)
            if wd < 0:
                err = ctypes.get_errno()
                raise ZeeError(
                    Z301_WATCHER_BACKEND_UNAVAILABLE,
                    f"inotify_add_watch({p}) failed: {os.strerror(err)}",
                )
            ref = f"{asset_id}#{index}"
            self._wd_to_path[wd] = str(p)
            self._wd_to_ref[wd] = ref
            self._path_to_ref[str(p)] = ref

        self._thread = threading.Thread(
            target=self._loop,
            args=(asset_id, on_event),
            name="zee-linux-watcher",
            daemon=True,
        )
        self._thread.start()

    def _try_reregister(self, path: str) -> bool:
        """Re-add an inotify watch for a decoy that was deleted or moved.

        Returns True when inotify_add_watch succeeds.  Called from _loop only.
        """
        try:
            p = Path(path)
            if not p.exists():
                return False
            wd = self._libc.inotify_add_watch(self._fd, str(p).encode(), DECOY_MASK)
            if wd < 0:
                return False
            ref = self._path_to_ref.get(path, "?#?")
            self._wd_to_path[wd] = path
            self._wd_to_ref[wd] = ref
            return True
        except OSError:
            return False

    def _loop(self, asset_id: str, on_event: OnEvent) -> None:
        import select

        buf_size = 8192
        while not self._stop_event.is_set():
            # Retry re-registration for any decoys that disappeared.
            with self._pending_lock:
                pending = list(self._pending_rewatch)
            for path in pending:
                if self._try_reregister(path):
                    with self._pending_lock:
                        self._pending_rewatch.discard(path)

            try:
                rlist, _, _ = select.select([self._fd], [], [], 0.5)
            except (OSError, ValueError):
                break
            if not rlist:
                continue
            try:
                data = os.read(self._fd, buf_size)
            except OSError as e:
                if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    continue
                logger.warning("inotify read failed: %s", e)
                break

            offset = 0
            while offset + _EVENT_HEADER.size <= len(data):
                wd, mask, _cookie, name_len = _EVENT_HEADER.unpack_from(data, offset)
                # Zee watches individual decoy files directly, so name_len is
                # always 0 here (the kernel only fills name when the watch
                # target is a directory). The +name_len arithmetic is kept
                # so a future switch to directory-level watches still parses
                # the variable-length trailing name correctly.
                offset += _EVENT_HEADER.size + name_len

                # IN_IGNORED fires after the kernel removes a stale wd
                # (following IN_DELETE_SELF or IN_MOVE_SELF).  The wd is now
                # invalid; queue the path for re-registration.
                if mask & IN_IGNORED:
                    path = self._wd_to_path.pop(wd, None)
                    self._wd_to_ref.pop(wd, None)
                    if path:
                        with self._pending_lock:
                            self._pending_rewatch.add(path)
                    continue

                path = self._wd_to_path.get(wd)
                if path is None:
                    continue
                # Only report touches that match our decoy mask.
                if not (mask & DECOY_MASK):
                    continue
                detail = _describe_mask(mask)
                op_class = _classify_mask(mask)
                event = TrapEvent.make(
                    source="decoy_touch",
                    confidence="high",
                    asset_id=asset_id,
                    decoy_path=path,
                    detail=detail,
                    op_class=op_class,
                    decoy_ref=self._wd_to_ref.get(wd),
                )
                try:
                    on_event(event)
                except Exception:
                    logger.exception("on_event callback raised")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        for wd in list(self._wd_to_path.keys()):
            try:
                self._libc.inotify_rm_watch(self._fd, wd)
            except OSError:
                pass
        self._wd_to_path.clear()
        self._wd_to_ref.clear()
        with self._pending_lock:
            self._pending_rewatch.clear()
        if self._fd >= 0:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = -1


def _classify_mask(mask: int) -> str:
    """Map an inotify event mask to read/change.

    Read-like: IN_ACCESS, IN_OPEN — what bulk readers do.
    Change-like: IN_MODIFY, IN_DELETE_SELF, IN_MOVE_SELF — what bulk
    readers do NOT do on a decoy under normal operation.
    """
    if mask & (IN_MODIFY | IN_DELETE_SELF | IN_MOVE_SELF):
        return "change"
    return "read"


def _describe_mask(mask: int) -> str:
    parts: list[str] = []
    if mask & IN_ACCESS:
        parts.append("read")
    if mask & IN_OPEN:
        parts.append("open")
    if mask & IN_MODIFY:
        parts.append("modify")
    if mask & IN_DELETE_SELF:
        parts.append("deleted")
    if mask & IN_MOVE_SELF:
        parts.append("moved")
    return "decoy " + ("+".join(parts) if parts else f"mask=0x{mask:x}")
