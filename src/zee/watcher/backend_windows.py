"""Windows watcher backend — ReadDirectoryChangesW via ctypes (spec §9).

Observes change notifications on the parent directories of decoys.
Does NOT observe reads — reliable read detection on Windows requires
Object Access auditing (SACL + Security event log), which is out of
scope for this MVP. Read detection is wired via canary URLs embedded
in decoys (see decoy/canary_token.py); ``canary_configured`` is
passed in only so capability() honestly reflects whether
ZEE_CANARY_BASE_URL is set by the operator.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import logging
import os
import sys
import threading
from pathlib import Path
from typing import Iterable, Optional

from ..errors import ZeeError, Z301_WATCHER_BACKEND_UNAVAILABLE, Z302_DECOY_PATH_NOT_FOUND
from ..events import TrapEvent
from .base import Capability, OnEvent

logger = logging.getLogger(__name__)

# Win32 constants we use
FILE_LIST_DIRECTORY = 0x0001
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
FILE_NOTIFY_CHANGE_ATTRIBUTES = 0x00000004
FILE_NOTIFY_CHANGE_SIZE = 0x00000008
FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010
FILE_NOTIFY_CHANGE_LAST_ACCESS = 0x00000020
FILE_NOTIFY_CHANGE_SECURITY = 0x00000100

CHANGE_MASK = (
    FILE_NOTIFY_CHANGE_FILE_NAME
    | FILE_NOTIFY_CHANGE_ATTRIBUTES
    | FILE_NOTIFY_CHANGE_SIZE
    | FILE_NOTIFY_CHANGE_LAST_WRITE
    | FILE_NOTIFY_CHANGE_LAST_ACCESS
    | FILE_NOTIFY_CHANGE_SECURITY
)

ACTION_NAMES = {
    1: "added",
    2: "removed",
    3: "modified",
    4: "renamed_from",
    5: "renamed_to",
}

INVALID_HANDLE_VALUE = wt.HANDLE(-1).value
BUFFER_SIZE = 8192


class WindowsWatcher:
    """ReadDirectoryChangesW-based watcher. Change detection only."""

    def __init__(self, *, canary_configured: bool = False) -> None:
        if sys.platform != "win32":
            raise ZeeError(
                Z301_WATCHER_BACKEND_UNAVAILABLE,
                f"WindowsWatcher requires win32; got {sys.platform}",
            )
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._handles: dict[str, wt.HANDLE] = {}  # dir_path -> handle
        self._watch_files: dict[str, set[str]] = {}  # dir_path -> { filenames }
        # (dir_path, filename) -> "asset_id#index" for the v0.3 decoy_ref payload.
        self._file_to_ref: dict[tuple[str, str], str] = {}
        self._threads: list[threading.Thread] = []
        self._stop_event = threading.Event()
        self._canary_configured = canary_configured

    def capability(self) -> Capability:
        if self._canary_configured:
            notes = (
                "ReadDirectoryChangesW for change detection on the parent "
                "directory. Read detection is delegated to canary URLs "
                "embedded in decoys by the seeder; the operator's "
                "external endpoint fires when an attacker dereferences "
                "a decoy URL (out-of-band — never re-enters Zee's local "
                "responder)."
            )
        else:
            notes = (
                "ReadDirectoryChangesW for change detection on the parent "
                "directory. Set ZEE_CANARY_BASE_URL to wire the canary "
                "URL path; without it, read-only attacker activity "
                "against a Windows decoy is not observed."
            )
        return Capability(
            backend_name="windows_readdirectorychangesw",
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
        self._stop_event.clear()

        # Group decoys by parent directory.
        by_dir: dict[str, set[str]] = {}
        for index, raw in enumerate(decoy_paths):
            p = Path(raw).expanduser().resolve()
            if not p.exists():
                raise ZeeError(Z302_DECOY_PATH_NOT_FOUND, str(p))
            by_dir.setdefault(str(p.parent), set()).add(p.name)
            self._file_to_ref[(str(p.parent), p.name)] = f"{asset_id}#{index}"

        for dir_path, filenames in by_dir.items():
            handle = self._open_dir(dir_path)
            self._handles[dir_path] = handle
            self._watch_files[dir_path] = filenames
            t = threading.Thread(
                target=self._loop,
                args=(dir_path, handle, asset_id, on_event),
                name=f"zee-win-watcher:{dir_path}",
                daemon=True,
            )
            t.start()
            self._threads.append(t)

    def _open_dir(self, dir_path: str) -> wt.HANDLE:
        CreateFileW = self._kernel32.CreateFileW
        CreateFileW.argtypes = [
            wt.LPCWSTR, wt.DWORD, wt.DWORD,
            ctypes.c_void_p, wt.DWORD, wt.DWORD, wt.HANDLE,
        ]
        CreateFileW.restype = wt.HANDLE
        handle = CreateFileW(
            dir_path,
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        if handle == INVALID_HANDLE_VALUE:
            err = ctypes.get_last_error()
            raise ZeeError(
                Z301_WATCHER_BACKEND_UNAVAILABLE,
                f"CreateFileW({dir_path}) failed: WinError {err}",
            )
        return handle

    def _loop(
        self,
        dir_path: str,
        handle: wt.HANDLE,
        asset_id: str,
        on_event: OnEvent,
    ) -> None:
        ReadDirectoryChangesW = self._kernel32.ReadDirectoryChangesW
        ReadDirectoryChangesW.argtypes = [
            wt.HANDLE, ctypes.c_void_p, wt.DWORD, wt.BOOL, wt.DWORD,
            ctypes.POINTER(wt.DWORD), ctypes.c_void_p, ctypes.c_void_p,
        ]
        ReadDirectoryChangesW.restype = wt.BOOL

        buf = ctypes.create_string_buffer(BUFFER_SIZE)
        bytes_returned = wt.DWORD(0)

        watch_set = self._watch_files.get(dir_path, set())

        while not self._stop_event.is_set():
            ok = ReadDirectoryChangesW(
                handle,
                buf, BUFFER_SIZE, False, CHANGE_MASK,
                ctypes.byref(bytes_returned), None, None,
            )
            if not ok or self._stop_event.is_set():
                break
            n = bytes_returned.value
            if n == 0:
                continue
            for action, filename in _parse_notifications(buf.raw[:n]):
                if filename not in watch_set:
                    continue
                full = str(Path(dir_path) / filename)
                detail = f"decoy {ACTION_NAMES.get(action, f'action={action}')}"
                # ReadDirectoryChangesW only fires on change-class
                # events (added / removed / modified / renamed). Reads
                # do not generate notifications here at all — read
                # detection on Windows runs out-of-band via canary URLs
                # in the decoy content (see decoy/canary_token.py) and
                # never re-enters this responder. Therefore every event
                # delivered through this path is change-class.
                trap = TrapEvent.make(
                    source="decoy_touch",
                    confidence="high",
                    asset_id=asset_id,
                    decoy_path=full,
                    detail=detail,
                    op_class="change",
                    decoy_ref=self._file_to_ref.get((dir_path, filename)),
                )
                try:
                    on_event(trap)
                except Exception:
                    logger.exception("on_event callback raised")

    def stop(self) -> None:
        self._stop_event.set()
        CloseHandle = self._kernel32.CloseHandle
        CloseHandle.argtypes = [wt.HANDLE]
        CloseHandle.restype = wt.BOOL
        # Close handles to unblock any pending ReadDirectoryChangesW.
        for h in self._handles.values():
            try:
                CloseHandle(h)
            except OSError:
                pass
        for t in self._threads:
            t.join(timeout=2.0)
        self._handles.clear()
        self._watch_files.clear()
        self._file_to_ref.clear()
        self._threads.clear()


def _parse_notifications(data: bytes) -> list[tuple[int, str]]:
    """Parse a FILE_NOTIFY_INFORMATION chain.

    Layout per record (little-endian):
      NextEntryOffset : DWORD
      Action          : DWORD
      FileNameLength  : DWORD (bytes)
      FileName        : WCHAR[FileNameLength/2]
    """
    out: list[tuple[int, str]] = []
    offset = 0
    while offset + 12 <= len(data):
        next_off = int.from_bytes(data[offset:offset + 4], "little")
        action = int.from_bytes(data[offset + 4:offset + 8], "little")
        name_len = int.from_bytes(data[offset + 8:offset + 12], "little")
        name_bytes = data[offset + 12:offset + 12 + name_len]
        try:
            filename = name_bytes.decode("utf-16-le")
        except UnicodeDecodeError:
            filename = ""
        out.append((action, filename))
        if next_off == 0:
            break
        offset += next_off
    return out
