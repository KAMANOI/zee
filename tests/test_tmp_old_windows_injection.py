"""TEMPORARY (reverted): proves the pre-fix Windows string was injectable."""
import shutil, subprocess, sys
import pytest


def _old_escape(s):
    return s.replace('"', '\\"').replace("\n", " ")


def _old_ps(title, body):
    return (
        '[reflection.assembly]::loadwithpartialname("System.Windows.Forms")|Out-Null;'
        '[reflection.assembly]::loadwithpartialname("System.Drawing")|Out-Null;'
        '$n=New-Object System.Windows.Forms.NotifyIcon;'
        '$n.Icon=[System.Drawing.SystemIcons]::Information;'
        '$n.Visible=$true;'
        f'$n.ShowBalloonTip(5000,"{_old_escape(title)}","{_old_escape(body)}",'
        '[System.Windows.Forms.ToolTipIcon]::Info);'
    )


@pytest.mark.skipif(sys.platform != "win32" or not shutil.which("powershell"), reason="Windows only")
@pytest.mark.parametrize("kind", ["subexpr", "quote"])
def test_old_code_runs_injected_command(kind, tmp_path):
    m = tmp_path / "pwn"
    title = {
        "subexpr": f"$(New-Item -ItemType File '{m}')",
        "quote": f'x"); New-Item -ItemType File \'{m}\'; ("',
    }[kind]
    r = subprocess.run(["powershell", "-NoProfile", "-Command", _old_ps(title, "b")],
                       capture_output=True, text=True, timeout=30)
    print(kind, "rc", r.returncode, r.stderr[-500:])
    assert m.exists(), f"{kind}: not injected"
