"""Static checks for how an AI-agent tool / sandbox is *configured*.

The other static checks look for malicious content. These look for the
ways an agent's tools and containment are commonly set up unsafely, so
a skill / MCP server / agent sample is flagged before its pattern is copied.
Nothing is executed: Python is parsed with `ast`, everything else is read
line by line with bounded patterns (no pattern here backtracks over a
whole file).

Flag codes:
    G205  model-controlled text interpolated into a shell command unquoted
    G206  computer/browser tool declared with a custom schema (no vendor
          safety classifiers apply)
    G207  tool input_schema and the handler's parameters do not match
    G208  command allowlist includes interpreters / scripts / inline code
    G209  network policy only logs (audit) or allows wildcard hosts/paths
    G210  passwordless sudo
    G211  screen sharing (VNC) without a password
    G602  a procedure reads the *contents* of a secret file

Best-effort heuristics (invariant I5): a flag means "look here", a clean
result is not a proof. A value Zee cannot see being validated is reported;
a value validated somewhere Zee cannot follow (another file's wrapper, a
decorator) is still reported. Known blind spots: data flow across files is
followed by function name only; JS/TS handler signatures (G207) and
non-literal schemas are not checked; shell scripts are matched per line.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

from .model import Flag, Severity

_MAX_BYTES = 2 * 1024 * 1024  # = static_checks._MAX_READ_BYTES: bigger files get G910 there
_MAX_HELD = 256 * 1024 * 1024  # text kept in memory for the whole tree
_MAX_LINE = 2000  # a longer line is cut: every line pattern stays bounded
_PY = {".py"}
_JS = {".js", ".ts", ".mjs", ".cjs"}
_SHELLISH = {".sh", ".bash", ".zsh", ".md", ".txt", ".yaml", ".yml", ".json",
             ".toml", ".cfg", ".ini", ""}
_CONFIGISH = {".yaml", ".yml", ".json", ".toml"}


def _flag(sev: Severity, code: str, msg: str, rel: str, line: int, snippet: str) -> Flag:
    snippet = " ".join(snippet.split())
    snippet = snippet if len(snippet) <= 80 else snippet[:77] + "…"
    return Flag(sev, code, msg, evidence=f"{rel}:{line}: {snippet}")


def _lines(text: str):
    for n, raw in enumerate(text.splitlines(), 1):
        yield n, raw[:_MAX_LINE]


# --- G205: unquoted interpolation into a shell command (Python, JS) --------

_SHELL_SINKS = {"system", "popen", "create_subprocess_shell", "getoutput",
                "getstatusoutput"}
_SUBPROC = {"run", "call", "check_call", "check_output", "Popen"}
_STDLIB = {"subprocess", "asyncio", "os", "shutil", "sys", "threading", "multiprocessing", "concurrent"}
_QUOTERS = {"quote", "shlex_quote", "shell_escape", "shellquote"}
_SAFE_CONVERT = {"int", "float", "bool", "len", "abs", "round"}


def _callee(node: ast.Call) -> str:
    f = node.func
    return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""


def _is_safe_call(node: ast.Call) -> bool:
    """shlex.quote / pipes.quote / a bare quote-style name, or int()/float()...
    A `.quote` on any other object (html, urllib) is not a shell quoter."""
    f = node.func
    if isinstance(f, ast.Name):
        return f.id in _QUOTERS or f.id in _SAFE_CONVERT
    return isinstance(f, ast.Attribute) and f.attr == "quote" \
        and isinstance(f.value, ast.Name) and f.value.id in ("shlex", "pipes")


def _on_stdlib(node: ast.Call) -> bool:
    f = node.func
    return isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id in _STDLIB


def _is_shell_call(node: ast.Call, helpers: set[str]) -> bool:
    name = _callee(node)
    # a helper is matched by name, but never on a stdlib module: `subprocess.run([...])` or
    # `asyncio.run(main())` is not the tree's own `def run(cmd)`
    if name in _SHELL_SINKS or (name in helpers and not _on_stdlib(node)):
        return True
    if name in _SUBPROC:  # only with shell=True
        return any(k.arg == "shell" and isinstance(k.value, ast.Constant)
                   and k.value.value is True for k in node.keywords)
    return False


def _py_functions(tree: ast.AST):
    return [n for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def _collect_helpers(tree: ast.AST, helpers: set[str], callers: dict[str, set[str]]) -> None:
    """Shell helpers = functions that pass one of their own parameters to a shell
    sink (directly or through another such function), matched by name across the
    whole tree: `self.shell(cmd)` -> `run(cmd)` -> create_subprocess_shell.
    This adds one file to the reverse call graph (callee name -> functions passing a
    parameter to it); `_close_helpers` walks it from the sinks once: linear."""
    for f in _py_functions(tree):
        params = {a.arg for a in f.args.args + f.args.kwonlyargs} - {"self", "cls"}
        for call in (n for n in ast.walk(f) if isinstance(n, ast.Call)):
            if any(isinstance(n, ast.Name) and n.id in params
                   for a in call.args for n in ast.walk(a)):
                if _is_shell_call(call, set()):
                    helpers.add(f.name)
                elif not _on_stdlib(call):  # `subprocess.run([...])` does not make f a caller of a `run` helper
                    callers.setdefault(_callee(call), set()).add(f.name)


def _close_helpers(helpers: set[str], callers: dict[str, set[str]]) -> set[str]:
    todo = list(helpers)
    while todo:
        for caller in callers.get(todo.pop(), ()):
            if caller not in helpers:
                helpers.add(caller)
                todo.append(caller)
    return helpers


def _walk_unsafe(root: ast.AST):
    """ast.walk that does not descend into shlex.quote(...) / int(...): what
    is inside them is made safe, so it must not re-enter as a finding."""
    stack = [root]
    while stack:
        n = stack.pop()
        yield n
        if isinstance(n, ast.Call) and _is_safe_call(n):
            continue
        stack.extend(ast.iter_child_nodes(n))


def _unsafe_parts(expr: ast.AST, safe_names: set[str]) -> ast.AST | None:
    """First sub-expression that interpolates a non-constant value into a
    string without quoting it (f-string, .format, %, +), or None."""
    def dynamic(v: ast.AST) -> bool:
        if isinstance(v, ast.Constant):
            return False
        if isinstance(v, ast.Name) and (v.id.isupper() or v.id in safe_names):
            return False
        if isinstance(v, ast.Attribute) and v.attr.isupper():
            return False
        if isinstance(v, ast.Subscript) and isinstance(v.value, (ast.Name, ast.Attribute)):
            base = v.value.id if isinstance(v.value, ast.Name) else v.value.attr
            if base.isupper():
                return False
        if isinstance(v, ast.Call) and _is_safe_call(v):
            return False
        return True

    for n in _walk_unsafe(expr):
        if isinstance(n, ast.JoinedStr):
            for fv in n.values:
                if isinstance(fv, ast.FormattedValue) and dynamic(fv.value):
                    spec = fv.format_spec
                    if isinstance(spec, ast.JoinedStr) and any(
                        isinstance(c, ast.Constant) and str(c.value).endswith(("d", "f"))
                        for c in spec.values
                    ):
                        continue  # {x:d} fails on a non-number
                    return n
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) \
                and n.func.attr == "format" and isinstance(n.func.value, ast.Constant):
            if any(dynamic(a) for a in n.args + [k.value for k in n.keywords]):
                return n
        elif isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Mod, ast.Add)) \
                and (isinstance(n.left, ast.Constant) and isinstance(n.left.value, str)):
            right = n.right.elts if isinstance(n.right, ast.Tuple) else [n.right]
            if any(dynamic(r) for r in right):
                return n
    return None


def _g205_python(rel: str, tree: ast.AST, helpers: set[str]) -> list[ast.AST]:
    hits: list[ast.AST] = []
    for fn in _py_functions(tree):
        # names whose every assignment is int()/float()/shlex.quote(): a type hint
        # proves nothing at run time, and one unsafe assignment cancels the rest
        # (flow-insensitive: a use before the conversion is not told apart)
        stores: dict[str, int] = {}  # every binding of a name: =, +=, for, tuple, with, :=
        for n in ast.walk(fn):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                stores[n.id] = stores.get(n.id, 0) + 1
        safe_stores: dict[str, int] = {}
        for n in ast.walk(fn):
            if isinstance(n, ast.Assign) and len(n.targets) == 1 \
                    and isinstance(n.targets[0], ast.Name) \
                    and isinstance(n.value, ast.Call) and _is_safe_call(n.value):
                safe_stores[n.targets[0].id] = safe_stores.get(n.targets[0].id, 0) + 1
        assigned = {k: v == stores.get(k) for k, v in safe_stores.items()}
        safe = {k for k, v in assigned.items() if v}
        # names that hold a built-up command: `parts = [.., f"key -- {t}"]`,
        # `cmd = "x " + t`, `parts.append(f"..{t}")`
        tainted: dict[str, list[ast.AST]] = {}

        def bad_in(expr: ast.AST) -> list[ast.AST]:
            first = _unsafe_parts(expr, safe)
            via = [h for x in _walk_unsafe(expr) if isinstance(x, ast.Name)
                   for h in tainted.get(x.id, [])]
            return ([first] if first is not None else []) + via

        for _ in range(3):  # a few hops: a = f"{t}"; b = [a]; c = " ".join(b)
            for n in ast.walk(fn):
                tgt = val = None
                if isinstance(n, ast.Assign) and len(n.targets) == 1 \
                        and isinstance(n.targets[0], ast.Name):
                    tgt, val = n.targets[0].id, n.value
                elif isinstance(n, ast.Expr) and isinstance(n.value, ast.Call) \
                        and isinstance(n.value.func, ast.Attribute) \
                        and n.value.func.attr in ("append", "extend", "insert") \
                        and isinstance(n.value.func.value, ast.Name) and n.value.args:
                    tgt, val = n.value.func.value.id, n.value.args[-1]
                if tgt is None:
                    continue
                if tgt in safe:
                    continue
                have = tainted.setdefault(tgt, [])
                if len(have) < 3:  # evidence shows 3; the cap keeps this linear
                    have += [h for h in bad_in(val)[:3] if all(h is not x for x in have)]
        for call in (n for n in ast.walk(fn) if isinstance(n, ast.Call)):
            if _is_shell_call(call, helpers) and call.args:
                hits += bad_in(call.args[0])
    # every command built from an unquoted value is a separate chance for
    # injection, so the evidence lists the first few, not only one
    return hits


_JS_QUOTER = r"(?:shell_?quote|shell_?escape|shlex|quote)\b"
_G205_JS = re.compile(
    r"\b(?:exec|execSync)\s*\(\s*(?:`[^`\n]{0,300}\$\{(?!\s*" + _JS_QUOTER + r")"
    r"|[\"'][^\"'\n]{0,300}[\"']\s*\+\s*(?!" + _JS_QUOTER + r")[A-Za-z_])", re.I)


# --- G206: custom definition of a computer/browser tool ---------------------

_G206_NAME = re.compile(
    r"""["']?name["']?\s*[:=]\s*["'](computer|browser|computer_use|screen)["']""")
_G206_VENDOR = re.compile(r"computer_20\d{6}|bash_20\d{6}|text_editor_20\d{6}")
_G206_SCHEMA = re.compile(r"input_schema|inputSchema")


# --- G208: allowlists that let the agent run code it wrote ------------------

_INTERP = {"bash", "sh", "zsh", "dash", "python", "python3", "node", "nodejs",
           "deno", "bun", "perl", "ruby", "php", "env", "xargs", "sudo",
           "eval", "exec", "npx", "source"}
_INLINE = re.compile(r"^\s*(?:bash|sh|zsh|python3?|node|perl|ruby|php)\s+-[ce]\b")
_G208_NAME = re.compile(r"(?<!dis)(?<!not_)(?<!un)(?<!not)allow|whitelist|permitted", re.I)
_G208_DENY = re.compile(r"dis_?allow|deny|denied|forbid|not_?allow", re.I)
_G208_EXT = re.compile(r"(?:^|_)[eE][xX][tT]|[a-z]Ext")  # case-sensitive: `text_allowlist` is not an extension list
_G208_JSL = re.compile(
    r"(?i)\b(?!\w*(?:disallow|deny|denied|forbid)|\w*(?-i:_ext|[a-z]Ext))\w{0,60}(?:allow|whitelist|permitted)\w{0,60}\s*[:=]\s*(?:new Set\(\s*)?\[([^\]\n]{0,2000})\]")
_QSTR = re.compile(r"""["']([^"'\n]{1,80})["']""")
_BASH_PERM = re.compile(r"^Bash(?:\(([^)]*)\))?$")


def _g208_bad(entry: str) -> bool:
    e = entry.strip()
    if _INLINE.match(e):
        return True
    first = e.split(None, 1)[0] if e.split() else ""
    base = first.rsplit("/", 1)[-1]
    return base in _INTERP or (base.endswith(".sh") and not base.startswith(".")
                               and len(e.split()) == 1)


def _g208_python(rel: str, tree: ast.AST) -> Flag | None:
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign):
            names = [t.id for t in n.targets if isinstance(t, ast.Name)]
            value = n.value
        elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
            names, value = [n.target.id], n.value
        else:
            continue
        if not any(_G208_NAME.search(x) and not _G208_DENY.search(x) and not _G208_EXT.search(x)
                   for x in names) \
                or value is None:
            continue
        if isinstance(value, ast.Call) and value.args:
            value = value.args[0]  # frozenset({...}) / set([...])
        elts = (value.keys if isinstance(value, ast.Dict) else
                value.elts if isinstance(value, (ast.Set, ast.List, ast.Tuple)) else [])
        for e in elts:
            if isinstance(e, ast.Constant) and isinstance(e.value, str) and _g208_bad(e.value):
                return _flag(Severity.MEDIUM, "G208",
                             "command allowlist includes an interpreter or script the agent "
                             "can use to run code it wrote",
                             rel, e.lineno, e.value)
    return None


def _g208_json(rel: str, text: str) -> Flag | None:
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return None
    stack = [data]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            for k, v in cur.items():
                if k in ("allow", "allowedTools", "allowed_tools") and isinstance(v, list):
                    for s in v:
                        m = isinstance(s, str) and _BASH_PERM.match(s)
                        if not m:
                            continue
                        arg = (m.group(1) or "*").split(":", 1)[0].strip()
                        if arg in ("*", "") or _g208_bad(arg):
                            return Flag(Severity.MEDIUM, "G208",
                                        "permission rule lets the agent run any interpreter "
                                        "or command (not a real allowlist)",
                                        evidence=f"{rel}: {s}"[:120])
                else:
                    stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur)
    return None


# --- G209: network policy that only logs, or allows wildcards ---------------

_NET_CONTEXT = re.compile(
    r"network_polic|egress|allowed_hosts|allowed_domains|endpoints|allow_hosts", re.I)
_G209_AUDIT = re.compile(
    r"""(?:^|[\s{,])["']?(?:enforcement|enforce_mode|network_mode)["']?\s*[:=]\s*"""
    r"""["']?(audit|log|log_only|monitor|permissive|report)\b""", re.I)
_G209_MODE = re.compile(r"""(?:^|[\s{,])["']?mode["']?\s*[:=]\s*["']?(audit|log|log_only|monitor|permissive)\b""", re.I)
_G209_DENY = re.compile(r"\s*[\"']?(?:deny|denied|disallow|blocklist|blocked)\w*[\"']?\s*[:=]", re.I)
_G209_OFF = re.compile(r"""(?:^|[\s{,])["']?enforce(?:ment)?["']?\s*[:=]\s*["']?(false|off|no)\b""", re.I)
_G209_HOST = re.compile(
    r"""["']?host(?:name)?["']?\s*[:=]\s*["']?([^"'\s,}]{0,200})""", re.I)
_G209_PATH = re.compile(r"""["']?path["']?\s*[:=]\s*["']?(/?\*{1,2}/?)["']?\s*[,}]?\s*$""")
_G209_LIST_KEY = re.compile(
    r"""^\s*["']?(?:allowed_hosts|allowed_domains|allow_hosts|allowed_destinations)["']?\s*[:=]\s*(.*)$""",
    re.I)


def _g209(rel: str, text: str) -> list[Flag]:
    if not _NET_CONTEXT.search(text):
        return []
    out: list[Flag] = []
    in_list_indent = -1
    deny_indent = -1  # inside a `deny:` block a wildcard is a refusal, not an allowance
    window: list[str] = []  # the 8 lines above: `mode` counts only inside a network block
    for n, line in _lines(text):
        indent = len(line) - len(line.lstrip())
        if in_list_indent >= 0:
            if line.strip() and indent <= in_list_indent and not line.lstrip().startswith("-"):
                in_list_indent = -1
            elif re.match(r"""\s*-\s*["']?[^"'\s]*\*""", line):
                out.append(_flag(Severity.MEDIUM, "G209",
                                 "network allowlist contains a wildcard host",
                                 rel, n, line))
                continue
        m = _G209_LIST_KEY.match(line)
        if m:
            rest = m.group(1).strip()
            if rest == "":
                in_list_indent = indent
            elif re.search(r"""["']?[\w.-]{0,100}\*""", rest):
                out.append(_flag(Severity.MEDIUM, "G209",
                                 "network allowlist contains a wildcard host", rel, n, line))
            continue
        if indent == 0 and line.strip() and not line.lstrip().startswith("#"):
            window = []  # a new top-level section: earlier network keys no longer apply
        if deny_indent >= 0 and line.strip() and indent <= deny_indent:
            deny_indent = -1
        if deny_indent < 0 and _G209_DENY.match(line):
            deny_indent = indent
        near_net = _NET_CONTEXT.search("\n".join(window))
        window = (window + [line])[-8:]
        if _G209_AUDIT.search(line) or _G209_OFF.search(line) \
                or (near_net and _G209_MODE.search(line)):
            out.append(_flag(Severity.MEDIUM, "G209",
                             "network policy is in log-only mode: violations are "
                             "recorded but let through (not enforced)", rel, n, line))
            continue
        hm = _G209_HOST.search(line)
        if hm and "*" in hm.group(1) and deny_indent < 0:
            out.append(_flag(Severity.MEDIUM, "G209",
                             "network rule uses a wildcard host", rel, n, line))
            continue
        if _G209_PATH.search(line):
            out.append(_flag(Severity.MEDIUM, "G209",
                             "network rule allows every path on its host", rel, n, line))
    return out


# --- G602 / G210 / G211: shell-ish text -------------------------------------

_SECRET = (r"(?:\.env(?!\.(?:example|sample|template|dist)\b)(?![\w-])|\.aws/credentials|"
           r"\.ssh/id_\w+(?!\w|\.pub\b)|\.npmrc|\.pypirc|\.netrc)")
_G602 = re.compile(
    r"\b(?:cat|head|tail|bat|strings|xxd|source)\s+[^\n|;&]{0,60}?" + _SECRET
    + r"|\bgrep\s+(?!-\w*[qcl]\b)[^\n|;&]{0,60}?" + _SECRET
    + r"|\b(?:read|open)\s+(?:the\s+)?contents?\s+of\s+(?:your\s+|the\s+)?" + _SECRET
    + r"|\b(?:print|show|display|dump|output)\s+(?:the\s+)?(?:contents?\s+of\s+)?"
    r"(?:your\s+|the\s+)?" + _SECRET, re.I)
_G602_NEG = re.compile(
    r"\b(?:never|do not|don't|dont|must not|without|avoid)\b|\bgrep\s+-\w*[qcl]\b|"
    r"存在だけ|読まない|読まず|開かない|禁止", re.I)
_G210 = re.compile(r"NOPASSWD\s*:|\bNOPASSWD\b\s*=|SUDO_NOPASSWD", re.I)
_G211_NOPW = re.compile(r"(?:^|\s)-{1,2}nopw\b|-SecurityTypes\s+None\b|\bSecurityTypes\s*=\s*None\b",
                        re.I)
_G211_AUTH = re.compile(r"(?:^|\s)-{1,2}(?:passwd|rfbauth|usepw|unixpw|passwdfile)\b", re.I)


_G211_START = re.compile(r"\bx11vnc\s+(?:[^\n]{0,500}?\s)?-{1,2}[A-Za-z]")
_APT = re.compile(r"\b(?:apt|apt-get|apk|yum|dnf|brew|pip3?)\b[^\n]{0,40}\binstall\b|\bpackages?\b", re.I)


def _logical_lines(text: str):
    """(first line number, joined text) with backslash continuations folded."""
    buf, start = [], 0
    for n, line in _lines(text):
        if not buf:
            start = n
        if line.rstrip().endswith("\\") and len(buf) < 20:
            buf.append(line.rstrip()[:-1])
            continue
        buf.append(line)
        yield start, " ".join(buf)[: _MAX_LINE * 4]
        buf = []
    if buf:
        yield start, " ".join(buf)[: _MAX_LINE * 4]


def _shellish(rel: str, text: str) -> list[Flag]:
    out: list[Flag] = []
    for n, line in _lines(text):
        if _G602.search(line) and not _G602_NEG.search(line):
            out.append(_flag(Severity.MEDIUM, "G602",
                             "reads the contents of a secret file (checking that it exists "
                             "is enough; do not print or load the secret)", rel, n, line))
        if _G210.search(line):
            out.append(_flag(Severity.MEDIUM, "G210",
                             "passwordless sudo (anything running as this user, including "
                             "an agent, becomes root)", rel, n, line))
    for n, line in _logical_lines(text):
        if _G211_NOPW.search(line):
            out.append(_flag(Severity.MEDIUM, "G211",
                             "screen sharing without a password", rel, n, line))
        elif _G211_START.search(line) and not _G211_AUTH.search(line) \
                and not _APT.search(line) and not line.lstrip().startswith(("#", "//")):
            out.append(_flag(Severity.MEDIUM, "G211",
                             "x11vnc started without a password option", rel, n, line))
    return out


# --- G207: tool schema vs handler parameters --------------------------------

_HANDLERS = ("execute", "__call__", "run", "call", "handle", "invoke")


def _literal_schema(cls: ast.ClassDef):
    for st in cls.body:
        tgt = val = None
        if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
            tgt, val = st.targets[0].id, st.value
        elif isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name):
            tgt, val = st.target.id, st.value
        if tgt in ("input_schema", "inputSchema", "parameters") and isinstance(val, ast.Dict):
            return st, val
    return None, None


def _g207(rel: str, tree: ast.AST) -> Flag | None:
    for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)):
        st, schema = _literal_schema(cls)
        if schema is None:
            continue
        props: set[str] | None = None
        required: list[str] = []
        for k, v in zip(schema.keys, schema.values):
            key = k.value if isinstance(k, ast.Constant) else None
            if key == "properties" and isinstance(v, ast.Dict):
                props = {x.value for x in v.keys if isinstance(x, ast.Constant)
                         and isinstance(x.value, str)}
            elif key == "required" and isinstance(v, (ast.List, ast.Tuple)):
                required = [x.value for x in v.elts if isinstance(x, ast.Constant)]
        if props is None:
            continue
        if any(isinstance(s, ast.Assign) and any(isinstance(t, ast.Name)
               and t.id == "validates_own_input" for t in s.targets) for s in cls.body):
            continue
        handler = next((s for name in _HANDLERS for s in cls.body
                        if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and s.name == name), None)
        if handler is None or handler.args.kwarg is not None:
            continue
        a = handler.args
        named = [x for x in a.posonlyargs + a.args + a.kwonlyargs if x.arg not in ("self", "cls")]
        n_def = len(a.defaults)
        no_default = {x.arg for x in a.posonlyargs + a.args[: len(a.args) - n_def]} | {
            x.arg for x, d in zip(a.kwonlyargs, a.kw_defaults) if d is None}
        params = {x.arg for x in named}
        if len(named) == 1 and named[0].arg not in props:
            continue  # f(self, arguments: dict): the handler unpacks the input itself
        problems = []
        if props - params:
            problems.append(f"schema declares {sorted(props - params)} the handler does not accept")
        if (no_default - {"self", "cls"}) - props:
            problems.append(f"handler requires {sorted((no_default - {'self', 'cls'}) - props)} "
                            "the schema never offers")
        optional_but_needed = ((no_default - {"self", "cls"}) & props) - set(required)
        if optional_but_needed:
            problems.append(f"{sorted(optional_but_needed)} optional in the schema "
                            "but required by the handler")
        if problems:
            return _flag(Severity.LOW, "G207",
                         "tool schema and handler parameters do not match",
                         rel, st.lineno, f"{cls.name}: " + "; ".join(problems))
    return None


def _python_flags(rel: str, tree: ast.AST, helpers: set[str]) -> list[Flag]:
    out: list[Flag] = []
    hits = sorted({getattr(h, "lineno", 0): h for h in _g205_python(rel, tree, helpers)}.items())
    if hits:
        out.append(Flag(Severity.MEDIUM, "G205",
                        "value interpolated into a shell command without quoting "
                        "(command injection if it comes from a model)",
                        evidence=f"{rel}: " + " | ".join(
                            f"{n}: {' '.join(ast.unparse(h).split())[:70]}"
                            for n, h in hits[:3])[:200]))
    out += [f for f in (_g207(rel, tree), _g208_python(rel, tree)) if f]
    return out


def _is_test(rel: str) -> bool:
    parts = rel.lower().replace("\\", "/").split("/")
    return any(x in ("test", "tests", "__tests__") for x in parts[:-1]) \
        or parts[-1].startswith(("test_", "conftest")) or ".test." in parts[-1]


# --- driver ------------------------------------------------------------------

def scan_tree(root: Path, paths: list[Path]) -> list[Flag]:
    """Run every check over the (already enumerated) files of a tree.
    Unreadable / oversized files are skipped here: the main pass reports them
    (G910 / G911)."""
    flags: list[Flag] = []
    seen: set[tuple[str, str]] = set()

    def add(f: Flag | None, rel: str) -> None:
        if f and (f.code, rel) not in seen:
            seen.add((f.code, rel))
            flags.append(f)

    texts: dict[str, str] = {}
    held = 0
    parsed: set[str] = set()
    helpers: set[str] = set()
    callers: dict[str, set[str]] = {}

    def gap(rel: str, why: str) -> None:
        add(Flag(Severity.LOW, "G911",
                 "file could not be analysed for agent-config checks; "
                 "its contents were not inspected",
                 evidence=f"{rel} ({why})"), rel)
    for p in paths:
        suf = p.suffix.lower()
        if suf not in _PY | _JS | _SHELLISH and p.name != "Dockerfile" \
                and not p.name.startswith("Dockerfile"):
            continue
        try:
            size = p.stat().st_size
            if size > _MAX_BYTES:
                continue
            if held + size > _MAX_HELD:
                flags.append(Flag(Severity.LOW, "G911",
                                  "tree too large to hold for agent-config checks; "
                                  "this file was not inspected",
                                  evidence=p.relative_to(root).as_posix()))
                continue
            text = p.read_text(encoding="utf-8", errors="ignore")
            held += size
        except (OSError, MemoryError):
            continue
        if "\0" in text:
            # a NUL in a text file must not switch the checks off (one byte would hide the file);
            # only an extensionless file that is not a script is treated as binary, as in the main pass
            if p.suffix == "" and not text.startswith("#!"):
                continue
            text = text.replace("\0", " ")
        rel = p.relative_to(root).as_posix()
        texts[rel] = text
        if suf in _PY:
            # one tree at a time: only the call-graph summary is kept, so memory does not grow
            # with every syntax tree in the artifact (each file is parsed again below)
            try:
                _collect_helpers(ast.parse(text), helpers, callers)
                parsed.add(rel)
            except (SyntaxError, ValueError):
                pass  # not Python we can read: the regex checks below still run
            except (RecursionError, MemoryError):
                gap(rel, "too deep or too large to parse")  # never silently "clean"

    helpers = _close_helpers(helpers, callers)
    for rel, text in texts.items():
        suf = Path(rel).suffix.lower()
        if rel in parsed:
            try:
                for f in _python_flags(rel, ast.parse(text), helpers):
                    add(f, rel)
            except (RecursionError, MemoryError, ValueError, SyntaxError):
                # a tree this deep can be parsed but not walked: say so, never "clean"
                gap(rel, "nesting too deep")
        if suf in _JS:
            if "child_process" in text:
                for n, line in _lines(text):
                    if _G205_JS.search(line):
                        add(_flag(Severity.MEDIUM, "G205",
                                  "value interpolated into a shell command without quoting "
                                  "(command injection if it comes from a model)",
                                  rel, n, line), rel)
                        break
            for n, line in _lines(text):
                m = _G208_JSL.search(line)
                if m and any(_g208_bad(s) for s in _QSTR.findall(m.group(1))):
                    add(_flag(Severity.MEDIUM, "G208",
                              "command allowlist includes an interpreter or script the agent "
                              "can use to run code it wrote", rel, n, line), rel)
                    break
        if suf == ".json":
            add(_g208_json(rel, text), rel)
        if suf in _CONFIGISH:
            for f in _g209(rel, text):
                add(f, rel)
        if suf in _PY | _JS | _CONFIGISH and not _is_test(rel):
            # judged per definition (the text around each name), not per file
            m = next((x for x in _G206_NAME.finditer(text)
                      if not _G206_VENDOR.search(text[max(0, x.start() - 400): x.end() + 600])),
                     None) if _G206_SCHEMA.search(text) else None
            if m:
                add(Flag(Severity.LOW, "G206",
                         "computer/browser tool declared with a custom schema: the API's "
                         "screen-specific safety classifiers (e.g. injected-instruction "
                         "detection) do not apply to it; use the vendor tool type or add "
                         "your own mitigations",
                         evidence=f"{rel}: {m.group(0)}"[:120]), rel)
        if suf in _SHELLISH or Path(rel).name.startswith("Dockerfile"):
            for f in _shellish(rel, text):
                add(f, rel)
    return flags
