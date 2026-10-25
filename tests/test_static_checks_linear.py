"""G203/G204 run in linear time and match exactly like the original regexes.

The plain regexes rescanned to the end of the line from every `curl` /
`exec(` / `atob(` (quadratic: `"curl " * 16000` took 3.9 s). The linear
matchers must return the same span and text as the original `search`.
"""

from __future__ import annotations

import random
import re

import pytest

from zee.gate.static_checks import _PATTERNS, scan_tree

from ._timing import assert_linear, best_of

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
# Linear work doubles when the input doubles; the quadratic regression this
# test guards against quadrupled (the original regexes took 3.9 s on
# "curl " * 16_000). A wall-clock budget in seconds measures the machine, not
# the algorithm: on a GitHub runner the old 5.0 s budget was exceeded by 0.09 s
# with the matchers unchanged (2026-10-25). The ratio cancels machine speed out,
# and the calibrated ceiling catches a constant-factor slowdown that the ratio
# alone would miss. Both live in tests/_timing.py, shared with the other
# timing tests.
#   measured 2026-10-25 (M1, Python 3.13): calibration 9.4 ms (spread 1 % over
#   5 runs), scan of the 2n input 1.78 s -> 189x. The ceiling below leaves
#   the detection boundary at 600 / 189 = about 3.2x: a constant-factor
#   regression above that fails, while a slower machine (which slows both
#   numbers) still passes. Stated this way because the ratio, not the
#   ceiling, is what the boundary follows (ASTRA 2026-10-25, 1dc26ff).
_MAX_CALIBRATED = 600


@pytest.mark.parametrize("name", sorted(_UNIT))
def test_pathological_g203_g204_input_stays_linear(tmp_path, name):
    unit, n = _UNIT[name]

    def scan(text):
        (tmp_path / "x.sh").write_text(text, encoding="utf-8")
        return best_of(lambda: scan_tree(tmp_path))

    t1, t2 = scan(unit * n), scan(unit * (2 * n))
    assert_linear(name, t1, t2, n, 2 * n, max_calibrated=_MAX_CALIBRATED)
