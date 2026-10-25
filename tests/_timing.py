"""Helpers for timing tests that judge the algorithm, not the machine.

A budget in seconds measures the runner. GitHub's runners are about 2.9x
slower than the development Mac (measured 2026-10-25: 5.09 s against 1.78 s on
the same scan), so an absolute budget eventually fails on a change that
touched nothing -- three of them did in a single day, on documentation-only
commits. What these helpers measure instead is

  1. growth -- how the time changes when the input doubles, which is what a
     quadratic regression shows up in, and
  2. the constant factor -- the time in units of a calibration workload run on
     the same machine, in the same process.

Both cancel machine speed out. The ratio alone would not notice a uniform
slowdown (10 s -> 20 s still doubles), which is what the calibration adds.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable

MAX_GROWTH = 3.0      # linear is ~2.0, quadratic ~4.0
REPEATS = 3           # other load can only make a run slower, so take the min

# The calibration workload: a plain regex sweep over 2 MB that cannot
# backtrack. Same engine, same process, no dependence on the code under test.
_CAL_RE = re.compile(r"zzzz")   # never matches
_CAL_TEXT = "ab" * 1_000_000    # 2 MB
_CAL_SWEEPS = 20


def calibration(repeats: int = REPEATS) -> float:
    """Machine speed in seconds, measured with the stdlib only."""
    best = float("inf")
    for _ in range(repeats):
        t = time.perf_counter()
        for _ in range(_CAL_SWEEPS):
            _CAL_RE.search(_CAL_TEXT)
        best = min(best, time.perf_counter() - t)
    return best


def best_of(run: Callable[[], object], repeats: int = REPEATS) -> float:
    """Shortest wall-clock time of `run` over `repeats` runs, in seconds.

    When `run` returns gate flags, a G910 among them fails here: that code
    means the file was over the read cap and never scanned, so the timing
    would be ~0 s and the test would pass without measuring anything.
    """
    best = float("inf")
    for _ in range(repeats):
        t = time.perf_counter()
        flags = run()
        best = min(best, time.perf_counter() - t)
        if flags is not None:
            assert not any(getattr(f, "code", None) == "G910" for f in flags), "file was not scanned"
    return best


def assert_linear(name: str, t1: float, t2: float, small: object, large: object,
                  max_calibrated: float, max_growth: float = MAX_GROWTH) -> None:
    """Fail if the work grew faster than linearly, or got slower by a constant factor.

    `max_calibrated` is the ceiling for `t2` in units of the calibration, and
    has to be measured per call site: it depends on how much work the input is.
    """
    assert t2 < t1 * max_growth, (
        f"{name}: {t1:.2f}s at {small} -> {t2:.2f}s at {large} "
        f"(x{t2 / t1:.1f}; linear is ~x2, quadratic ~x4)"
    )
    cal = calibration()
    assert t2 < cal * max_calibrated, (
        f"{name}: {t2:.2f}s at {large} is {t2 / cal:.0f}x the calibration "
        f"({cal * 1000:.1f}ms); the ceiling is {max_calibrated}x. The growth "
        f"ratio was x{t2 / t1:.1f}, so this is a constant-factor slowdown, "
        f"not a slower machine."
    )
