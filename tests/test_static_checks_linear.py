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


_BIG = {
    "g203_curl_flood": "curl " * 400_000,
    "g203_wget_flood": "wget x " * 290_000,
    "g204_exec_flood": "exec(" * 400_000,
    "g204_atob_flood": "atob(" * 400_000,
    "g204_b64_flood": "base64.b64decode(" * 120_000,
}


@pytest.mark.parametrize("name", sorted(_BIG))
def test_pathological_g203_g204_input_is_fast(tmp_path, name):
    (tmp_path / "x.sh").write_text(_BIG[name], encoding="utf-8")
    t = time.perf_counter()
    flags = scan_tree(tmp_path)
    elapsed = time.perf_counter() - t
    assert not any(f.code == "G910" for f in flags)  # really scanned
    assert elapsed < 5.0, f"{name}: {elapsed:.2f}s"
