"""Keep every test out of the real user's home.

Product code resolves its state dir from HOME / XDG_STATE_HOME (see
zee.telemetry.events_log.default_log_dir), so a test that forgets to pass
an explicit path writes into the real ~/.local/state/zee (gate quarantine,
events log, canary registry) or ~/.zee. Two guards:

1. `_isolated_home` (autouse, per test): HOME / USERPROFILE / XDG_STATE_HOME
   point into the test's tmp_path. Subprocesses inherit it.
2. `_real_home_untouched` (autouse, per session): snapshots the real state
   dirs before any test runs and fails the run if anything was added,
   removed or resized there.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from zee.telemetry.events_log import default_log_dir

# Resolved at import time, before any fixture touches the environment.
_REAL_DIRS = sorted({default_log_dir(), Path.home() / ".zee"})


def _snapshot() -> dict[str, int]:
    snap: dict[str, int] = {}
    for d in _REAL_DIRS:
        if not d.exists():
            continue
        snap[str(d)] = -1
        for p in d.rglob("*"):
            try:
                snap[str(p)] = p.lstat().st_size if p.is_file() else -1
            except OSError:
                pass
    return snap


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path_factory, monkeypatch):
    home = tmp_path_factory.mktemp("home")
    (home / ".local" / "state").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("XDG_STATE_HOME", str(home / ".local" / "state"))


@pytest.fixture(autouse=True, scope="session")
def _real_home_untouched():
    before = _snapshot()
    yield
    after = _snapshot()
    if before != after:
        added = sorted(set(after) - set(before))
        removed = sorted(set(before) - set(after))
        changed = sorted(k for k in set(before) & set(after) if before[k] != after[k])
        pytest.fail(
            "tests wrote to the real home state dirs "
            f"{[str(d) for d in _REAL_DIRS]}: added={added[:10]} "
            f"removed={removed[:10]} changed={changed[:10]}",
            pytrace=False,
        )
