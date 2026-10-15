"""v0.13.2: the macOS notifier passes title/body as argv, never as script text."""
import zee.notifier.local as local


def test_macos_title_and_body_are_argv_not_script(monkeypatch):
    calls = []
    monkeypatch.setattr(local.subprocess, "run", lambda cmd, **kw: calls.append(cmd))
    evil = 'x" & (do shell script "touch /tmp/pwn") & "'
    local._notify_macos(evil, evil + "\\")
    (cmd,) = calls
    script_parts = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-e"]
    assert script_parts == [
        "on run argv",
        "display notification (item 2 of argv) with title (item 1 of argv)",
        "end run",
    ]
    assert cmd[-3:] == ["--", evil, evil + "\\"]


def test_leading_hyphen_title_is_not_an_option(monkeypatch):
    calls = []
    monkeypatch.setattr(local.subprocess, "run", lambda cmd, **kw: calls.append(cmd))
    local._notify_macos("-e", "do shell script \"id\"")
    (cmd,) = calls
    assert cmd[cmd.index("end run") + 1] == "--"


import shutil, subprocess, sys
import pytest


@pytest.mark.skipif(sys.platform != "darwin" or not shutil.which("osascript"), reason="macOS only")
def test_osascript_receives_argv_verbatim():
    """Round trip through the real osascript without showing a notification."""
    evil = ['-e', 'x" & (do shell script "id") & "\\', "", "line1\nline2"]
    out = subprocess.run(
        ["osascript", "-e", "on run argv", "-e",
         "set AppleScript's text item delimiters to (ASCII character 0)",
         "-e", "return argv as text", "-e", "end run", "--", *evil],
        capture_output=True, text=True, timeout=10,
    ).stdout.rstrip("\n")
    assert out.split("\x00") == evil
