"""G205-G211 / G602: agent tool and sandbox configuration checks.

Every check has a deliberately unsafe input that must be flagged and a safe
way of writing the same thing that must stay clean. The unsafe inputs are
written for this suite; they only mimic the shapes (no upstream code).
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from zee.gate import static_checks


def _scan(tmp_path: Path, files: dict[str, str]) -> dict[str, list[str]]:
    for rel, body in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    out: dict[str, list[str]] = {}
    for f in static_checks.scan_tree(tmp_path):
        out.setdefault(f.code, []).append(f.evidence)
    return out


# ---- G205 -----------------------------------------------------------------

_RUN = (
    "import asyncio\n"
    "async def run(cmd):\n"
    "    return await asyncio.create_subprocess_shell(cmd)\n"
)

_UNSAFE_TOOL = (
    "from .run import run\n"
    "class Tool:\n"
    "    async def shell(self, command):\n"
    "        return await run(command)\n"
    "    async def __call__(self, action, text):\n"
    "        if action == 'key':\n"
    "            parts = ['xdotool', f'key -- {text}']\n"
    "            return await self.shell(' '.join(parts))\n"
)

_SAFE_TOOL = (
    "import shlex\n"
    "from .run import run\n"
    "class Tool:\n"
    "    async def shell(self, command):\n"
    "        return await run(command)\n"
    "    async def __call__(self, action, text, x):\n"
    "        x = int(x)\n"
    "        parts = ['xdotool', f'key -- {shlex.quote(text)}', f'mousemove {x}']\n"
    "        return await self.shell(' '.join(parts))\n"
)


def test_g205_flags_unquoted_text_through_helper_and_list(tmp_path):
    got = _scan(tmp_path, {"tools/run.py": _RUN, "tools/tool.py": _UNSAFE_TOOL})
    assert [e for e in got["G205"] if "tools/tool.py" in e]
    assert "text" in got["G205"][0]


def test_g205_quoted_or_int_is_clean(tmp_path):
    got = _scan(tmp_path, {"tools/run.py": _RUN, "tools/tool.py": _SAFE_TOOL})
    assert "G205" not in got


def test_g205_direct_sinks(tmp_path):
    got = _scan(tmp_path, {
        "a.py": "import os\ndef f(name):\n    os.system('ls ' + name)\n",
        "b.py": "import subprocess\ndef f(n):\n    subprocess.run(f'ls {n}', shell=True)\n",
    })
    assert len(got["G205"]) == 2


def test_g205_no_shell_is_clean(tmp_path):
    got = _scan(tmp_path, {
        "a.py": "import subprocess\ndef f(n):\n    subprocess.run(['ls', n])\n"
                "    subprocess.run(f'ls {n}')\n",  # string without shell=True is not a shell call
        "b.py": "import os\nLS='ls'\ndef f():\n    os.system(f'{LS} -l')\n",
    })
    assert "G205" not in got


def test_g205_js_template_literal(tmp_path):
    bad = "const { exec } = require('child_process');\nexec(`xdotool key -- ${text}`);\n"
    good = ("const { exec } = require('child_process');\n"
            "exec(`xdotool key -- ${shellQuote(text)}`);\n")
    assert "G205" in _scan(tmp_path / "bad", {"a.js": bad})
    assert "G205" not in _scan(tmp_path / "good", {"a.js": good})


def test_g205_quote_inside_is_clean_and_annotation_is_not_proof(tmp_path):
    ok = ("import os, shlex\ndef f(x, y):\n"
          "    os.system('echo ' + shlex.quote(f'hello {x}'))\n"
          "    os.system('echo %s' % (shlex.quote(y),))\n")
    bad = "import os\ndef f(x: int):\n    os.system(f'echo {x}')\n"
    assert "G205" not in _scan(tmp_path / "ok", {"a.py": ok})
    assert "G205" in _scan(tmp_path / "bad", {"a.py": bad})


def test_python_adversarial_shapes_stay_fast_and_do_not_crash(tmp_path):
    n = 3000
    chain = "import os\n" + "".join(f"def f{i}(c):\n    return f{i + 1}(c)\n" for i in range(n)) \
        + f"def f{n}(c):\n    os.system(c)\n"
    selfref = "import os\ndef g(t, c):\n" + "    c = f'{c} {t}'\n" * n + "    os.system(c)\n"
    deep = "def h(x):\n    return f'{" + "+".join(["x"] * 1500) + "}'\n"
    for name, body in (("chain", chain), ("selfref", selfref), ("deep", deep)):
        (tmp_path / f"{name}.py").write_text(body)
    t = time.perf_counter()
    got = _scan(tmp_path, {})
    assert time.perf_counter() - t < 5.0
    assert any("selfref.py" in e for e in got["G205"])


def test_size_gap_is_not_silent(tmp_path):
    # between the old 512 KiB cut-off and the main pass's 2 MiB limit the checks still run
    pad = "# " + "x" * 100 + "\n"
    body = "import os\ndef f(n):\n    os.system('ls ' + n)\n" + pad * 6000
    assert len(body) > 600_000
    assert "G205" in _scan(tmp_path, {"big.py": body})


def test_safe_spellings_stay_clean(tmp_path):
    got = _scan(tmp_path, {
        "k.md": "show your key: `cat ~/.ssh/id_ed25519.pub` ; `cat .env.example`\n",
        "d.py": "DISALLOWED_COMMANDS = {'bash', 'sh'}\nALLOWED_EXTENSIONS = {'.sh', '.py'}\n",
        "d.ts": "const disallowedCommands = ['bash'];\n",
        "t.py": "class T:\n    input_schema = {'properties': {'a': {}, 'b': {}}}\n"
                "    def execute(self, arguments: dict):\n        return arguments\n",
        "l.yaml": "logging:\n  mode: audit\nnetwork_policies: {}\n",
    })
    for code in ("G602", "G208", "G207", "G209"):
        assert code not in got, (code, got.get(code))
    assert "G602" in _scan(tmp_path / "e", {"a.md": "run `cat .env.local`\n"})
    assert "G209" in _scan(tmp_path / "j", {"p.json": '{"egress": {"enforcement": "audit"}}'})


# ---- G206 -----------------------------------------------------------------

def test_g206_custom_computer_tool(tmp_path):
    custom = ('TOOL = {"name": "computer", "description": "x",\n'
              ' "input_schema": {"type": "object", "properties": {}}}\n')
    vendor = ('TOOL = {"type": "computer_20251124", "name": "computer",\n'
              ' "display_width_px": 1024, "input_schema": {}}\n')
    assert "G206" in _scan(tmp_path / "c", {"tools.py": custom})
    assert "G206" not in _scan(tmp_path / "v", {"tools.py": vendor})
    assert "G206" not in _scan(tmp_path / "t", {"tests/test_x.py": custom})


# ---- G207 -----------------------------------------------------------------

_MISMATCH = (
    "class T:\n"
    "    name = 'x'\n"
    "    input_schema = {'type': 'object', 'properties': {'a': {}, 'b': {}},\n"
    "                    'required': ['a']}\n"
    "    def execute(self, a):\n"
    "        return a\n"
)
_MATCH = _MISMATCH.replace("def execute(self, a)", "def execute(self, a, b=None)")


def test_g207_mismatch_and_match(tmp_path):
    got = _scan(tmp_path / "m", {"t.py": _MISMATCH})
    assert "G207" in got and "['b']" in got["G207"][0]
    assert "G207" not in _scan(tmp_path / "ok", {"t.py": _MATCH})


def test_g207_required_with_default_and_extra_required(tmp_path):
    required_default = _MATCH.replace("def execute(self, a, b=None)", "def execute(self, a=1, b=None)")
    extra = _MATCH.replace("def execute(self, a, b=None)", "def execute(self, a, b, c)")
    assert "G207" in _scan(tmp_path / "d", {"t.py": required_default})
    assert "G207" in _scan(tmp_path / "e", {"t.py": extra})


def test_g207_kwargs_handler_is_skipped(tmp_path):
    kw = _MISMATCH.replace("def execute(self, a)", "def execute(self, **kwargs)")
    assert "G207" not in _scan(tmp_path, {"t.py": kw})


# ---- G208 -----------------------------------------------------------------

def test_g208_python_allowlist(tmp_path):
    bad = "ALLOWED_COMMANDS = {'ls', 'cat', 'node', 'init.sh'}\n"
    bad2 = "allowed = ['ls', 'python -c']\n"
    good = "ALLOWED_COMMANDS = {'ls', 'cat', 'grep', 'git'}\n"
    assert "G208" in _scan(tmp_path / "a", {"s.py": bad})
    assert "G208" in _scan(tmp_path / "b", {"s.py": bad2})
    assert "G208" not in _scan(tmp_path / "g", {"s.py": good})


def test_g208_claude_permission_rules(tmp_path):
    bad = '{"permissions": {"allow": ["Bash(ls:*)", "Bash(node:*)"]}}'
    wide = '{"permissions": {"allow": ["Bash"]}}'
    good = '{"permissions": {"allow": ["Bash(ls:*)", "Bash(git status)", "Read"]}}'
    assert "G208" in _scan(tmp_path / "a", {".claude/settings.json": bad})
    assert "G208" in _scan(tmp_path / "w", {".claude/settings.json": wide})
    assert "G208" not in _scan(tmp_path / "g", {".claude/settings.json": good})


def test_g208_js_allowlist(tmp_path):
    bad = "const allowedCommands = new Set(['ls', 'bash']);\n"
    good = "const allowedCommands = new Set(['ls', 'cat']);\n"
    assert "G208" in _scan(tmp_path / "a", {"s.ts": bad})
    assert "G208" not in _scan(tmp_path / "g", {"s.ts": good})


# ---- G209 -----------------------------------------------------------------

_POLICY_BAD = (
    "network_policies:\n"
    "  api:\n"
    "    endpoints:\n"
    "      - host: api.example.com\n"
    "        enforcement: audit\n"
)
_POLICY_WILD = (
    "network_policies:\n"
    "  api:\n"
    "    endpoints:\n"
    "      - host: \"*.example.com\"\n"
    "        enforcement: enforce\n"
)
_POLICY_LIST = "egress:\n  allowed_hosts:\n    - api.example.com\n    - \"*\"\n"
_POLICY_GOOD = (
    "network_policies:\n"
    "  api:\n"
    "    endpoints:\n"
    "      - host: api.example.com\n"
    "        enforcement: enforce\n"
    "        rules:\n"
    "          - allow: { method: GET, path: \"/v1/sessions/sesn_123\" }\n"
    "          - allow: { method: POST, path: \"/v1/work/*/heartbeat\" }\n"
)


@pytest.mark.parametrize("name,body", [
    ("audit", _POLICY_BAD), ("wild", _POLICY_WILD), ("list", _POLICY_LIST),
    ("anypath", _POLICY_GOOD.replace("/v1/sessions/sesn_123", "/**")),
])
def test_g209_flags(tmp_path, name, body):
    assert "G209" in _scan(tmp_path, {"policy.yaml": body})


def test_g209_enforced_exact_policy_is_clean(tmp_path):
    assert "G209" not in _scan(tmp_path, {"policy.yaml": _POLICY_GOOD})
    # 'mode: audit' outside any network policy is not a network setting
    assert "G209" not in _scan(tmp_path / "x", {"app.yaml": "logging:\n  mode: audit\n"})


# ---- G602 -----------------------------------------------------------------

def test_g602_reads_secret_contents(tmp_path):
    bad = "# Setup\nRun `cat .env` and check the key.\nThen grep KEY .env\n"
    good = ("# Setup\nNever read the contents of `.env`.\n"
            "Check it exists: `[ -f .env ] && grep -q '^KEY=.' .env && echo set`\n"
            "Count only: `grep -c '^KEY=.' .env`\nCopy `.env.example` to `.env`.\n"
            "cat .env.example\n")
    assert "G602" in _scan(tmp_path / "b", {"SKILL.md": bad})
    assert "G602" not in _scan(tmp_path / "g", {"SKILL.md": good})


# ---- G210 / G211 ----------------------------------------------------------

def test_g210_g211(tmp_path):
    docker = ('RUN apt-get install -y sudo x11vnc\n'
              'RUN echo "u ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers\n')
    start = "(x11vnc -display $DISPLAY \\\n   -forever \\\n   -nopw) &\n"
    bare = "x11vnc -display :1 -forever &\n"
    got = _scan(tmp_path / "a", {"Dockerfile": docker, "start.sh": start})
    assert "G210" in got and "G211" in got
    assert len(got["G211"]) == 1  # the apt-get line is a package list, not a start
    assert "G211" in _scan(tmp_path / "b", {"start.sh": bare})
    ok = "x11vnc -display :1 -forever -rfbauth /run/vnc.pass &\n"
    assert "G211" not in _scan(tmp_path / "c", {"start.sh": ok})
    assert "G210" not in _scan(tmp_path / "d", {"Dockerfile": "RUN echo hi\n"})


# ---- verdict + linear time -------------------------------------------------

def test_flags_reach_the_verdict(tmp_path):
    from zee.gate.inspector import inspect_source
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "SKILL.md").write_text("# s\n")
    (tmp_path / "src" / "t.py").write_text(
        "import os\ndef f(n):\n    os.system('ls ' + n)\n")
    v = inspect_source(tmp_path / "src", kind="skill", quarantine_base=tmp_path / "q")
    assert any(f.code == "G205" for f in v.flags)
    assert v.risk_level.value == "MEDIUM"


@pytest.mark.parametrize("body", [
    "cat " * 20000,
    "x11vnc " * 20000,
    "host: " + "*" * 100000,
    "NOPASSWD " * 20000,
    "allowed_hosts: " + "a*" * 50000,
    "- " * 100000,
])
def test_adversarial_lines_stay_fast(tmp_path, body):
    (tmp_path / "p.yaml").write_text("network_policies:\n" + body + "\n")
    (tmp_path / "s.sh").write_text(body + "\n" + (body + " \\\n") * 25)
    t = time.perf_counter()
    static_checks.scan_tree(tmp_path)
    assert time.perf_counter() - t < 3.0
