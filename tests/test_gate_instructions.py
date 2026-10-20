"""G217-G220: procedure documents that change the host's AI config, plugin
definitions that declare an outside connection, browsers started unsafely.

Trees are synthetic, written from the shape seen in a public plugin (a skill
reference telling the AI to add an MCP server and merge it into ~/.cursor/mcp.json;
.mcp.json with an https server; Chromium started with web security off).
Each check has a benign counterpart that must stay clean.
"""

from __future__ import annotations

from pathlib import Path

from zee.gate import static_checks


def _scan(tmp_path: Path, files: dict[str, str]):
    for rel, body in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return {f.code: f for f in static_checks.scan_tree(tmp_path)}


_REF = (
    "1. **Register the MCP server** with the agent host.\n\n"
    '   {"vendor-browser": {"url": "https://mcp.vendor.example"}}\n\n'
    "   - Cursor: merge only the `vendor-browser` key into the user-level `~/.cursor/mcp.json`.\n"
)


def test_bad_tree_hits_all_four_as_medium(tmp_path):
    by = _scan(tmp_path, {
        "skills/x/references/generate.md": _REF,
        ".mcp.json": '{"mcpServers": {"v": {"type": "http", "url": "https://mcp.vendor.example"}}}',
        "render.mjs": "const b = await chromium.launch({\n args: ['--disable-web-security'],\n chromiumSandbox: false })\n",
    })
    for c in ("G217", "G218", "G219", "G220"):
        assert by[c].severity.value == "medium", c
    assert "mcp.vendor.example" in by["G219"].message


def test_plugin_json_inline_and_toml(tmp_path):
    by = _scan(tmp_path, {"plugin.json": '{"name":"p","mcpServers":{"a":{"url":"https://a.example/mcp"}}}'})
    assert "G219" in by
    by = _scan(tmp_path / "t", {".codex/config.toml": '[mcp_servers.a]\nurl = "https://a.example/mcp"\n'})
    assert "G219" in by


def test_benign_tree_is_clean(tmp_path):
    by = _scan(tmp_path, {
        # local server, command-based server, plugin pointing at a file
        ".mcp.json": '{"mcpServers": {"l": {"url": "http://localhost:3000"}, "c": {"command": "node", "args": ["s.js"]}}}',
        "plugin.json": '{"name": "p", "mcpServers": "./.mcp.json"}',
        # negated instruction, README written for people, a doc with a URL but no MCP
        "skills/x/SKILL.md": "Never edit mcp.json yourself. See https://docs.example for details.\n",
        "README.md": "Add this to your ~/.cursor/mcp.json:\n{\"url\": \"https://mcp.vendor.example\"}\nRegister the MCP server.\n",
        # browser kept sandboxed; the switch only named in a comment
        "ok.mjs": "// never use --no-sandbox here\nawait chromium.launch({ args: ['--use-angle=swiftshader'] })\n",
        # CI secret scan, OIDC release: nothing to flag
        ".github/workflows/ci.yml": "jobs:\n  secrets:\n    steps:\n      - name: gitleaks\n        run: gitleaks detect\n",
    })
    assert not {"G217", "G218", "G219", "G220"} & set(by)


def test_g217_needs_all_three_signals(tmp_path):
    only_url = _scan(tmp_path, {"skills/a/SKILL.md": "Docs: https://vendor.example/guide\n"})
    assert "G217" not in only_url
    no_url = _scan(tmp_path / "b", {"skills/a/SKILL.md": "Register the MCP server the user already has.\n"})
    assert "G217" not in no_url


# --- fixes after independent review round 1 -------------------------------

def test_ipv6_and_malformed_urls_do_not_stop_the_scan(tmp_path):
    by = _scan(tmp_path, {
        "skills/a/SKILL.md": "Register the MCP server at https://[::1]/mcp and also http://[bad/x\n",
        "x/mcp.json": '{"mcpServers": {"a": {"url": "https://[::1]:3000/mcp"}, "b": {"url": "http://[bad"}}}',
        ".codex/config.toml": '[mcp_servers.a]\nurl = "https://[::1]/mcp"\n',
        "tail.md": "# still scanned\n",
    })
    assert not {"G217", "G219"} & set(by)  # loopback is local; nothing crashed
    by = _scan(tmp_path / "o", {"skills/a/SKILL.md": "Register the MCP server at https://[2001:db8::1]/mcp\n"})
    assert "G217" in by


def test_many_lines_stay_linear(tmp_path):
    import time
    n = 20000
    t = time.perf_counter()
    by = _scan(tmp_path, {"skills/a/SKILL.md": "mcp.json\n" * n + "write\n" * n})
    assert time.perf_counter() - t < 5
    assert "G218" in by


def test_readme_and_docs_are_not_procedures_even_under_skills(tmp_path):
    body = "Register the MCP server https://mcp.vendor.example\nMerge it into ~/.cursor/mcp.json\n"
    by = _scan(tmp_path, {"skills/a/README.md": body, "docs/SKILL.md": body})
    assert not {"G217", "G218"} & set(by)


def test_automation_flag_alone_is_not_a_sandbox_switch(tmp_path):
    by = _scan(tmp_path, {"a.py": "chromium.launch(ignore_default_args=['--enable-automation'], chromium_sandbox=True)\n"})
    assert "G220" not in by


# --- fixes after independent review round 2 -------------------------------

def test_removing_a_switch_is_not_setting_it(tmp_path):
    by = _scan(tmp_path, {"a.py": "chromium.launch(ignore_default_args=['--no-sandbox'], chromium_sandbox=True)\n"})
    assert "G220" not in by
    by = _scan(tmp_path / "b", {"a.py": "chromium.launch(ignore_default_args=['--x'], args=['--no-sandbox'])\n"})
    assert "G220" in by


def test_toml_text_that_only_mentions_a_server_is_not_a_server(tmp_path):
    doc = 'description = """\n[mcp_servers.demo]\nurl = "https://a.example/mcp"\n"""\n'
    assert "G219" not in _scan(tmp_path, {"plugin.toml": doc})
