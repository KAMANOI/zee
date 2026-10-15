"""The Windows notifier passes title/body through the environment, never as script text."""
import base64
import os
import shutil
import subprocess
import sys

import pytest

import zee.notifier.local as local

EVIL = ['x"; Write-Output PWNED; "', "$(Write-Output PWNED)", "`$x `\" ' ''", "a;b|c&d", "line1\nline2"]


def test_windows_title_and_body_are_env_not_script(monkeypatch):
    calls = []
    monkeypatch.setattr(local.subprocess, "run", lambda cmd, **kw: calls.append((cmd, kw)))
    title, body = EVIL[0], EVIL[1]
    local._notify_windows(title, body)
    ((cmd, kw),) = calls
    assert not any(title in a or "PWNED" in a for a in cmd)
    assert cmd == ["powershell", "-NoProfile", "-NonInteractive", "-Command", local._WIN_SCRIPT]
    assert kw["env"]["ZEE_TITLE"] == title and kw["env"]["ZEE_BODY"] == body


def test_nul_in_value_does_not_raise():
    # A NUL can't go into an environment block; the notifier must swallow it.
    assert local._notify_windows("a\x00b", "c") in (True, False)


@pytest.mark.skipif(sys.platform != "win32" or not shutil.which("powershell"), reason="Windows only")
@pytest.mark.parametrize("value", EVIL + ["\u65e5\u672c\u8a9e", "a\r\nb\rc"])
def test_real_win_script_keeps_values_as_text(value, tmp_path):
    """Run the production _WIN_SCRIPT on real PowerShell, then read back what
    ShowBalloonTip stored (Base64, so CR/LF and non-ASCII compare exactly).
    A $(...) in the value must not run (no marker file appears)."""
    marker = tmp_path / "pwn"
    value = value.replace("Write-Output PWNED", f"New-Item -ItemType File '{marker}'")
    readback = (
        "[Console]::Out.Write([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("
        "$n.BalloonTipTitle+[char]0+$n.BalloonTipText)));$n.Dispose()"
    )
    r = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", local._WIN_SCRIPT + readback],
        env={**os.environ, "ZEE_TITLE": value, "ZEE_BODY": value + "!"},
        capture_output=True, text=True, timeout=30,
    )
    assert base64.b64decode(r.stdout).decode() == value + "\x00" + value + "!", r.stderr
    assert not marker.exists()
