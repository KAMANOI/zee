"""Keep every test out of the real user's home.

Product code resolves its state dir from HOME / XDG_STATE_HOME (see
zee.telemetry.events_log.default_log_dir), so a test that forgets to pass
an explicit path writes into the real ~/.local/state/zee (gate quarantine,
events log, canary registry) or ~/.zee. Two guards:

1. Isolation: at import (before collection) and again per test, HOME /
   USERPROFILE / XDG_STATE_HOME point into a temp dir. Subprocesses that
   inherit os.environ follow it.
2. Watchdog: the real state dirs are snapshotted at import and compared in
   pytest_sessionfinish; any added/removed/modified entry makes the run
   fail (exit status forced to 1, so an xfail-marked test can't absorb it).
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from zee.telemetry.events_log import default_log_dir

# Resolved before anything below touches the environment.
_REAL_HOME = Path.home()
_REAL_DIRS = sorted({
    _REAL_HOME / ".local" / "state" / "zee",
    _REAL_HOME / ".zee",
    default_log_dir(),  # honours a shell-set XDG_STATE_HOME
})


def _snapshot() -> dict[str, tuple]:
    snap: dict[str, tuple] = {}
    for d in _REAL_DIRS:
        for p in [d, *d.rglob("*")] if d.exists() else []:
            try:
                st = p.lstat()
            except OSError as e:  # unreadable entries still count
                snap[str(p)] = ("err", e.errno)
                continue
            snap[str(p)] = (st.st_mode, st.st_size, st.st_mtime_ns)
    return snap


def _point_home_at(home: Path) -> None:
    (home / ".local" / "state").mkdir(parents=True, exist_ok=True)
    os.environ["HOME"] = str(home)
    os.environ["USERPROFILE"] = str(home)
    os.environ["XDG_STATE_HOME"] = str(home / ".local" / "state")


_BEFORE = _snapshot()
# For the one live sandbox test that must place a (self-removing) sentinel
# under the real home to prove the sandbox denies reads there.
os.environ["ZEE_TEST_REAL_HOME"] = str(_REAL_HOME)
# Session-wide fallback so module-level code and broader-scope fixtures
# never see the real home either.
_point_home_at(Path(tempfile.mkdtemp(prefix="zee-test-home-")))


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path_factory, monkeypatch):
    home = tmp_path_factory.mktemp("home")
    (home / ".local" / "state").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("XDG_STATE_HOME", str(home / ".local" / "state"))


def pytest_sessionfinish(session, exitstatus):
    after = _snapshot()
    if after == _BEFORE:
        return
    added = sorted(set(after) - set(_BEFORE))
    removed = sorted(set(_BEFORE) - set(after))
    changed = sorted(k for k in set(_BEFORE) & set(after) if _BEFORE[k] != after[k])
    session.config.get_terminal_writer().line(
        "\nREAL HOME TOUCHED: tests wrote to the real state dirs "
        f"{[str(d) for d in _REAL_DIRS]}\n  added={added[:10]}\n"
        f"  removed={removed[:10]}\n  changed={changed[:10]}\n"
        "  (a running zee watch writing its own log at the same moment "
        "also trips this; re-run to tell them apart)",
        red=True,
    )
    session.exitstatus = pytest.ExitCode.TESTS_FAILED
