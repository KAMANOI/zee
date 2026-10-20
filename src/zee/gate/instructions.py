"""Static checks for a *procedure document* that makes an AI assistant change
its own environment, and for plugin definitions that declare an outside
connection. Nothing is executed; files are read as text, line by line, with
bounded patterns ("near" = within `_WIN` lines).

Flag codes (all MEDIUM: a person reads them, nothing is blocked by itself):
    G217  a procedure (SKILL.md, references/, commands/ ...) tells the AI to
          register an outside MCP server / endpoint on the host
    G218  a procedure tells the AI to write into an AI-tool or developer-tool
          config file (mcp.json, settings.json, config.toml, CLAUDE.md ...)
    G219  a plugin definition (.mcp.json, plugin.json, config.toml ...)
          declares an outside connection (a non-local http(s) MCP server)
    G220  a browser is started with its sandbox or web security switched off

A flag states what the files say, not who wrote them or why. Safe wording
("back it up first", "the user signs in") does not clear a flag: the point is
that a person sees, before install, that the procedure edits the host.

Best-effort heuristics (invariant I5): a clean result is not a proof. A
registration described in other words, a config path built from pieces, a
connection declared in a language Zee does not parse, or a command-based
(stdio) server is not seen. A negated sentence on the same line ("never edit
mcp.json") is skipped; a negation on another line is not.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

from .model import Flag, Severity
from .tampering import _CODE, _CONFIG, _DOC, _WIN, _flag, _hits, _near

# --- which documents are "procedures for an AI" ----------------------------
# README / docs are written for people ("add this to your mcp.json"); a skill,
# a command, an agent or a reference file is what the assistant itself follows.
_PROC_DIRS = {"skills", "skill", "references", "commands", "agents", "prompts", "playbooks"}
_PROC_NAMES = {"skill.md", "agents.md", "claude.md", "gemini.md", "instructions.md"}


def _is_procedure(rel: str) -> bool:
    parts = Path(rel.lower()).parts
    return parts[-1] in _PROC_NAMES or any(p in _PROC_DIRS for p in parts[:-1])


_NEG = re.compile(r"\b(?:never|do not|don't|must not|should not|shall not|cannot|can't|without)\b", re.I)


def _verb_hits(lines: list[str], pat: re.Pattern[str]) -> list[int]:
    """Lines where `pat` matches and is not part of a same-line negation
    ("never edit ...", "do not add ...")."""
    out = []
    for i, ln in enumerate(lines):
        for m in pat.finditer(ln):
            before = ln[max(0, m.start() - 40):m.start()]
            if not _NEG.search(before):
                out.append(i)
                break
    return out


# --- G217: register an outside MCP server ----------------------------------
_MCP = re.compile(r"\bMCP\b|mcpServers|mcp_servers|\bmcp\s+add\b|add-mcp", re.I)
_REG = re.compile(
    r"\b(?:register|registers|registering|add|adds|adding|configure|configures|configuring|connect|"
    r"connects|connecting|install|installing|set\s+up|setting\s+up|enable|enabling|merge|append)\b|"
    r"\b(?:claude|codex|gemini|cursor|opencode|amp)\s+mcp\s+add\b|\badd-mcp\b|\bmcp\s+add\b|"
    r"登録|追加|接続|設定して|組み込", re.I)
_URL = re.compile(r"https?://[^\s\"'<>)\]`,]+", re.I)
_LOCAL_HOST = re.compile(r"^(?:localhost|127\.\d+\.\d+\.\d+|\[?::1\]?|0\.0\.0\.0)$", re.I)


def _outside_url(line: str) -> str | None:
    for m in _URL.finditer(line):
        host = (urlparse(m.group(0)).hostname or "")
        if host and not _LOCAL_HOST.match(host):
            return host
    return None


# --- G218: write into an AI / developer tool config ------------------------
_CFG_PATH = re.compile(
    r"(?<![\w-])(?:\.?mcp\.json|claude_desktop_config\.json|\.claude\.json|\.claude[/\\]settings(?:\.local)?\.json|"
    r"\.cursor[/\\](?:mcp\.json|rules)|\.codex[/\\]config\.toml|\.gemini[/\\]settings\.json|"
    r"\.vscode[/\\](?:mcp|settings)\.json|\.windsurf[/\\]\w+|\.continue[/\\]config\.\w+|"
    r"opencode\.jsonc?|\.cursorrules|\.windsurfrules|CLAUDE\.md|AGENTS\.md|GEMINI\.md|"
    r"\.zshrc|\.bashrc|\.zprofile|\.bash_profile)(?![\w-])")
_WRITE_VERB = re.compile(
    r"\b(?:merge|append|add|write|edit|modify|create|insert|update|overwrite|patch|put|inject|"
    r"rewrite|save|store|set)\b|>>\s*\S|\bsed\s+-i|\btee\b|書き込|追記|編集|変更|追加|作成", re.I)

# --- G219: plugin definition declares an outside MCP server ----------------
_DEF_NAME = re.compile(r"mcp|plugin|marketplace|settings|config", re.I)
_SERVER_KEYS = {"mcpservers", "mcp_servers", "mcp"}
_URL_KEYS = {"url", "serverurl", "httpurl", "endpoint", "baseurl", "server_url"}
_TOML_TABLE = re.compile(r"^\s*\[\s*(?:mcp_servers|mcpServers|mcp)\b[^\]]*\]")
_TOML_URL = re.compile(r"^\s*(?:url|server_url|endpoint|http_url)\s*=\s*[\"'](https?://[^\"']+)", re.I)


def _servers(node, out: list[tuple[str, str]], in_servers: bool = False) -> None:
    """Collect (server name, url) for every server entry with an outside http(s) URL."""
    if isinstance(node, dict):
        for k, v in node.items():
            if in_servers and isinstance(v, dict):
                for uk, uv in v.items():
                    if uk.lower() in _URL_KEYS and isinstance(uv, str) and (h := _outside_url(uv)):
                        out.append((str(k), h))
            _servers(v, out, in_servers=(k.lower() in _SERVER_KEYS and isinstance(v, dict)))
    elif isinstance(node, list):
        for v in node:
            _servers(v, out, in_servers)


def _g219(rel: str, name: str, text: str, lines: list[str], nums: list[int], suf: str) -> list[Flag]:
    found: list[tuple[str, str]] = []
    if suf == ".json" and _DEF_NAME.search(name):
        try:
            _servers(json.loads(text), found)
        except (ValueError, RecursionError):
            pass
    elif suf == ".toml" and _DEF_NAME.search(name):
        in_tbl = False
        for ln in lines:
            if ln.lstrip().startswith("["):
                in_tbl = bool(_TOML_TABLE.match(ln))
            elif in_tbl and (m := _TOML_URL.match(ln)) and (h := _outside_url(m.group(1))):
                found.append(("(toml)", h))
    if not found:
        return []
    srv, host = found[0]
    # point at the line that holds the host
    at = next((i for i, ln in enumerate(lines) if host in ln), 0)
    more = f" (+{len(found) - 1} more)" if len(found) > 1 else ""
    return [_flag(Severity.MEDIUM, "G219",
                  f"plugin / MCP definition declares an outside connection: server '{srv}' at {host}{more}; "
                  f"the tool's data and requests can reach that host once it is enabled",
                  rel, nums[at] if lines else 1, lines[at] if lines else "")]


# --- G220: browser sandbox / web security off ------------------------------
_NO_SANDBOX = re.compile(
    r"--no-sandbox|--disable-setuid-sandbox|--disable-web-security|--disable-site-isolation-trials|"
    r"--disable-features=[^\s\"',]*(?:IsolateOrigins|SitePerProcess)|"
    r"\bchromiumSandbox\b[\"']?\s*[:=]\s*(?:false|False)|\bchromium_sandbox\s*=\s*False|"
    r"\bignore_default_args\b[^\n]{0,60}--enable-automation|\bwebSecurity\s*:\s*false", re.I)


def file_flags(rel: str, name: str, text: str, lines: list[str], nums: list[int], suf: str) -> list[Flag]:
    """All G217-G220 flags for one file (one flag per code per file)."""
    flags: list[Flag] = []
    if suf in _DOC and suf != "" and _is_procedure(rel):
        # G217: an MCP word, a registering verb and an outside URL close together
        urls = [i for i, ln in enumerate(lines) if _outside_url(ln)]
        mcp, reg = _verb_hits(lines, _MCP), _verb_hits(lines, _REG)
        for i in urls:
            if any(abs(j - i) <= _WIN for j in mcp) and any(abs(j - i) <= _WIN for j in reg):
                flags.append(_flag(Severity.MEDIUM, "G217",
                                   f"procedure tells the AI to register an MCP server at an outside host "
                                   f"({_outside_url(lines[i])})", rel, nums[i], lines[i]))
                break
        # G218: a config path and a writing verb on the same line or the next two
        writes = _verb_hits(lines, _WRITE_VERB)
        hit = next((i for i in _hits(lines, _CFG_PATH) if any(i <= j <= i + 2 for j in writes)), None)
        if hit is not None:
            flags.append(_flag(Severity.MEDIUM, "G218",
                               "procedure tells the AI to write into an AI-tool / developer-tool config "
                               "file (mcp.json, settings.json, config.toml, CLAUDE.md, shell profile ...)",
                               rel, nums[hit], lines[hit]))
    if suf in _CONFIG:
        flags += _g219(rel, name, text, lines, nums, suf)
    if suf in _CODE | _CONFIG:
        if hits := _hits(lines, _NO_SANDBOX, None, False):
            i = hits[0]
            flags.append(_flag(Severity.MEDIUM, "G220",
                               "starts a browser with its sandbox or web security switched off "
                               "(--no-sandbox / --disable-web-security / chromiumSandbox: false)",
                               rel, nums[i], lines[i]))
    return flags

