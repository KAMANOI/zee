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
    assert cmd[-2:] == [evil, evil + "\\"]
