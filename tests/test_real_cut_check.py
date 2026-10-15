"""scripts/real_cut_check.py: the pass verdict (Codex #6 / 4-persona #4)."""
import importlib.util
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location(
    "real_cut_check", Path(__file__).resolve().parent.parent / "scripts" / "real_cut_check.py")
rcc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rcc)

GOOD = {"cut": {"ok": True}, "restore": {"ok": True, "by": "finally"}, "stopped": True, "came_back": True}


def test_all_good_passes():
    assert rcc.passed(GOOD) is True


@pytest.mark.parametrize("change", [
    {"cut": {"ok": False}},                                     # cut failed, traffic stopped anyway
    {"restore": {"ok": False, "by": "finally", "error": "Z606"}},  # restore raised
    {"restore": {"ok": True, "by": "safety-timer"}},            # not the normal path
    {"restore": None},
    {"stopped": False},
    {"came_back": False},
])
def test_anything_else_fails(change):
    assert rcc.passed({**GOOD, **change}) is False


# ── .github/workflows/real-cut.yml (4-persona #5 #12 #13, Codex #7) ────

WF = (Path(__file__).resolve().parent.parent / ".github" / "workflows" / "real-cut.yml").read_text()


def test_workflow_runs_on_main_with_path_filter_and_never_on_prs():
    assert "branches: [main, feat/self-defense-20261015]" in WF
    assert "paths:" in WF and "src/zee/responder/**" in WF and "src/zee/recovery/**" in WF
    assert "pull_request" not in WF


def test_workflow_checkout_keeps_no_token():
    assert WF.count("actions/checkout@") == WF.count("persist-credentials: false") == 3


def test_workflow_keeps_the_exit_code_under_bash_e():
    assert WF.count("--safety-seconds 45 || rc=$?") == 2  # linux, macos
    assert "\n          rc=$?\n" not in WF


def test_windows_safety_task_checked_before_and_kept_unless_rules_gone():
    create = WF.index("schtasks /create")
    assert WF.index('throw "safety task not created', create) < WF.index("real_cut_check.py", create)
    delete = WF.index("schtasks /delete")
    assert WF.index("No rules match the specified criteria") < delete
    assert "if ($gone) { schtasks /delete" in WF


# ── scripts/verify-real-macos.sh (Codex #8 #9, 4-persona #10 #11) ──────

SH_PATH = Path(__file__).resolve().parent.parent / "scripts" / "verify-real-macos.sh"
SH = SH_PATH.read_text()


@pytest.mark.skipif(__import__("sys").platform == "win32", reason="bash on Windows runners may be the WSL stub")
def test_mac_script_parses():
    import subprocess
    assert subprocess.run(["bash", "-n", str(SH_PATH)]).returncode == 0


def test_mac_script_aborts_before_cutting_when_the_state_cannot_be_read():
    first_cut = SH.index("real_cut_check.py")
    for needle in ('abort "pfctl -s info failed"', 'abort "pf status unreadable"',
                   'abort "networksetup failed"', 'abort "network service list unreadable"',
                   "Zee pf rules already loaded", 'is a symbolic link', 'abort "cannot create $OUT"'):
        assert SH.index(needle) < first_cut, needle
    assert "mkdir -p" not in SH  # a pre-planted name must make mkdir fail


def test_mac_script_exit_code_covers_the_after_state_and_stops_the_timer():
    assert "trap on_exit EXIT" in SH and "trap 'exit 130' INT HUP TERM" in SH
    assert 'kill "$SAFETY_PID"' in SH.split("on_exit() {", 1)[1].split("}", 1)[0]
    assert '[ "$v" = true ] || rc=1' in SH and "exit $rc" in SH
    # Zee's own restore is judged before the script's cleanup touches anything.
    assert SH.index("snapshot after-zee") < SH.index("restore_everything || rc=1")


def test_mac_script_snapshot_fails_when_an_anchor_read_fails():
    """Codex re-review: a failed pfctl read must not look like an empty anchor."""
    body = SH.split("snapshot() {", 1)[1].split("\n}\n", 1)[0]
    assert 'r="$(pfctl -a "$a" -s rules 2>/dev/null)" || return 1' in body
    assert "|| true" not in body


# ── v0.13.1: IPv6 ─────────────────────────────────────────────────────

V6 = {"before": {"reachable": True}, "during": {"reachable": False}, "after": {"reachable": True}}


@pytest.mark.parametrize("change, status", [
    ({}, "passed"),
    ({"before": {"reachable": False}}, "unmeasured"),  # no IPv6 path: never a pass
    ({"during": {"reachable": True}}, "failed"),
    ({"after": {"reachable": False}}, "failed"),
])
def test_ipv6_status(change, status):
    assert rcc.ipv6_status({**V6, **change}) == status


@pytest.mark.parametrize("status, expect", [("passed", True), ("unmeasured", False), ("failed", False)])
def test_required_ipv6_must_pass(status, expect):
    assert rcc.passed({**GOOD, "ipv6": {"status": status}}, require_ipv6=True) is expect
    # Not required: "unmeasured" leaves the IPv4 verdict; a measured failure still fails.
    assert rcc.passed({**GOOD, "ipv6": {"status": status}}) is (status != "failed")


def test_linux_jobs_require_ipv6_and_link_the_same_backend_ip6tables():
    assert "--url6 'http://[2001:db8::1]:8081/' --require-ipv6" in WF
    assert 'src6="/usr/sbin/ip6tables-${src##*-}"' in WF
