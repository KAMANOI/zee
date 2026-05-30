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

        for raw in decoy_paths:
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
            self._wd_to_path[wd] = str(p)

        self._thread = threading.Thread(
            target=self._loop,
            args=(asset_id, on_event),
            name="zee-linux-watcher",
            daemon=True,
        )
        self._thread.start()

    def _loop(self, asset_id: str, on_event: OnEvent) -> None:
        import select

        buf_size = 8192
        while not self._stop_event.is_set():
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
                offset += _EVENT_HEADER.size + name_len
                path = self._wd_to_path.get(wd)
                if path is None:
                    continue
                # Only report touches that match our decoy mask.
                if not (mask & DECOY_MASK):
                    continue
                detail = _describe_mask(mask)
                event = TrapEvent.make(
                    source="decoy_touch",
                    confidence="high",
                    asset_id=asset_id,
                    decoy_path=path,
                    detail=detail,
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
        if self._fd >= 0:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = -1


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
