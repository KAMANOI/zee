"""Local desktop notification (spec §5 step 1, §10).

Must work without network. Always also prints to stderr so the message
survives even when the desktop notification backend is missing.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import sys

logger = logging.getLogger(__name__)


def notify_local(title: str, body: str) -> bool:
    """Best-effort desktop notification.

    Returns True if a desktop backend was attempted, False if not available.
    Always also emits to stderr so the message is preserved either way.
    """
    print(f"[zee] {title}: {body}", file=sys.stderr, flush=True)

    if sys.platform.startswith("linux"):
        return _notify_linux(title, body)
    if sys.platform == "darwin":
        return _notify_macos(title, body)
    if sys.platform == "win32":
        return _notify_windows(title, body)
    return False


def _notify_linux(title: str, body: str) -> bool:
    if not shutil.which("notify-send"):
        return False
    try:
        subprocess.run(
            ["notify-send", title, body],
            check=False,
            timeout=3,
        )
        return True
    except (subprocess.SubprocessError, OSError) as e:
        logger.warning("notify-send failed: %s", e)
        return False


def _notify_macos(title: str, body: str) -> bool:
    script = f'display notification "{_escape(body)}" with title "{_escape(title)}"'
    try:
        subprocess.run(
            ["osascript", "-e", script],
            check=False,
            timeout=3,
        )
        return True
    except (subprocess.SubprocessError, OSError) as e:
        logger.warning("osascript failed: %s", e)
        return False


def _notify_windows(title: str, body: str) -> bool:
    ps = (
        '[reflection.assembly]::loadwithpartialname("System.Windows.Forms")|Out-Null;'
        '[reflection.assembly]::loadwithpartialname("System.Drawing")|Out-Null;'
        '$n=New-Object System.Windows.Forms.NotifyIcon;'
        '$n.Icon=[System.Drawing.SystemIcons]::Information;'
        '$n.Visible=$true;'
        f'$n.ShowBalloonTip(5000,"{_escape(title)}","{_escape(body)}",'
        '[System.Windows.Forms.ToolTipIcon]::Info);'
    )
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            check=False,
            timeout=5,
        )
        return True
    except (subprocess.SubprocessError, OSError) as e:
        logger.warning("powershell toast failed: %s", e)
        return False


def _escape(s: str) -> str:
    return s.replace('"', '\\"').replace("\n", " ")
