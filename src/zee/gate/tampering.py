"""Static checks for a "tampering plugin": an artifact that rewrites a
legitimate package on the host, re-applies itself on every start, and injects
a prompt the installer cannot read.

Nothing is executed. Every file is read as text and matched line by line with
bounded patterns; "near" means within `_WIN` lines. A flag states what was
found in the file, not who wrote it.

Flag codes:
    G212  HIGH    writes into / replaces files of another package
                  (node_modules, site-packages, a resolved module path),
                  usually after copying the original to a *.bak
    G213  MEDIUM  re-applies itself every time the host starts
                  (autoApplyOnStart and equivalents)
    G214  HIGH    the text injected into the system prompt / agent
                  instructions is encrypted, encoded or fetched, so the
                  installer cannot read it in plain text
    G215  MEDIUM  patches other, already-installed plugins / extensions
    G216  MEDIUM  the README (or other docs) contains instructions aimed at
                  an AI assistant ("paste this to your assistant, it only
                  installs")

Best-effort heuristics (invariant I5): a flag means "look here", a clean
result is not a proof. Renamed variables, split expressions or a payload
fetched under another name pass. A benign tool that patches node_modules on
purpose (patch-package style) is flagged G212 by design: the verdict is a
block until a person has read it.
"""

from __future__ import annotations

import bisect
import re
from pathlib import Path

from . import textfile
from .model import Flag, Severity

_MAX_BYTES = 2 * 1024 * 1024  # = static_checks._MAX_READ_BYTES (bigger files get G910 there)
# A line longer than _LONG (minified code) is read in overlapping pieces, so "near" means within a
# few hundred characters there instead of "anywhere on the one line", and nothing is skipped.
_LONG, _CHUNK, _STEP = 2000, 600, 300
_WIN = 12  # "near" = within this many lines
_CODE = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".py", ".sh", ".bash", ".zsh", ".ps1"}
_SHELL = {".sh", ".bash", ".zsh", ".ps1"}
_CONFIG = {".json", ".yaml", ".yml", ".toml", ".cfg", ".ini"}
_DOC = {".md", ".markdown", ".txt", ".rst", ".html", ".htm", ""}
_COMMENT = re.compile(r"^\s*(?://|#|\*|/\*|<!--)")

# --- G212: write into another package -------------------------------------
_PKG_TARGET = re.compile(
    r"(?<![\w-])(?:node_modules|site-packages|dist-packages)(?![\w-])|"
    r"require\.resolve\s*\(|import\.meta\.resolve")
_PKG_SKIP = re.compile(r"node_modules['\"]?(?:\s*,\s*['\"]|[/\\])\.(?:cache|bin|vite|tmp|prisma)(?![\w.-])")
_WRITE = re.compile(
    r"\b(?:writeFile|writeFileSync|appendFile|appendFileSync|copyFile|copyFileSync|"
    r"cpSync|renameSync|rename|symlinkSync|symlink)\s*\(|"
    r"\bfs\.(?:promises\.)?(?:cp|rm|rename|writeFile|copyFile)\b|"
    r"\bshutil\.(?:copy\w*|move)\b|\bos\.(?:replace|rename)\s*\(|"
    r"\.write_(?:text|bytes)\s*\(|\bopen\([^)\n]*['\"][wa][b+]*['\"]|"
    r"\bsed\s+-i|(?<=\s)>>?\s*\S*(?:node_modules|site-packages)|\bpatch\s+-p")
_WRITE_SH = re.compile(r"\b(?:cp|mv|ln)\s+-?\w*\s")  # shell verbs: too common as words in JS / Python
_COPY = re.compile(r"copy|cpSync|(?:^|\.)cp\b|^cp\s")  # a write match that is a copy (source, destination)
_ASSIGNED = re.compile(r"^\s*(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=(?!=)")
_STR = re.compile(r"'(?:\\.|[^'\\\n])*'|\"(?:\\.|[^\"\\\n])*\"|`(?:\\.|[^`\\])*`")  # quoted text on one line
_CODE_STR = re.compile(r"\$\{|\'\'\'|\"\"\"|(?<![\w])[rRbB]?[fF][rRbB]?[\"']")
_UNQUOTE_SUFFIX = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".py"}  # never shell: `...` / $() run commands
_BACKUP = re.compile(r"\.(?:[A-Za-z0-9_-]+\.)?(?:bak|orig|backup|original)\b|[_-](?:bak|orig|backup)\b",
                     re.I)


def _unquote(line: str) -> str:
    """JS / Python line with quoted text emptied, so a word in plain text ("explain how
    decrypt(x) works") is not read as a call. A line that may hold a string able to run code
    (`${`, an f-string prefix, triple quotes) is kept whole: that may flag plain text, but a
    regular expression cannot split such strings safely, and it must never hide a call."""
    if _CODE_STR.search(line):
        return line
    return _STR.sub('""', line)


# --- G213: re-apply on every start ----------------------------------------
_REAPPLY = re.compile(
    r"auto[_-]?re?[_-]?appl(?:y|ied)[_-]?(?:on[_-]?)?(?:start|launch|boot|startup|load)\w*|"
    r"re[_-]?appl(?:y|ied)[_-]?on[_-]?(?:start|launch|boot|startup|load)\w*|"
    r"auto[_-]?re[_-]?appl(?:y|ied)\b|apply[_-]?on[_-]?(?:start|launch|boot)\w*",
    re.I)
# what follows the matched name: `": false`, `= false;` (checked right after the name, not at line end)
_OFF_VALUE = re.compile(r"[\"']?\s*[:=]\s*[\"']?(?:false|0|off|no)(?![\w.])", re.I)

# --- G214: injected prompt the installer cannot read ----------------------
_SINK = re.compile(
    r"(?:system[_ -]?prompt|system[_ -]?message|append[_-]?system|prepend[_-]?system|"
    r"post[_-]?prompt|pre[_-]?prompt|default[_-]?prompt|prompt[_-]?inject\w*|inject\w*[_-]?prompt|"
    r"agent[_ -]?instructions|system[_ -]?instructions|custom[_ -]?instructions)"
    r"\w*[^\n]{0,40}?(?:=|\+=|:|\()", re.I)
_DECRYPT = re.compile(
    r"createDecipher(?:iv)?|subtle\.decrypt|\bdecrypt\w*\s*\(|\bFernet\b|AES\.new|\bnacl\.|"
    r"\bsecretbox\b|\bgpg\s+(?:-d|--decrypt)|\bopenssl\s+(?:enc|aes)|\bunseal\w*\s*\(|"
    r"\bdeobfuscat\w*\s*\(", re.I)
_BLOB = re.compile(r"[A-Za-z0-9+/_-]{200,}={0,2}|(?:[0-9a-fA-F]{2}){100,}")
_FETCH = re.compile(
    r"\bfetch\s*\(|\baxios\b|\brequests\.(?:get|post)\b|\burlopen\s*\(|\bhttps?\.get\s*\(|"
    r"\bcurl\s|\bwget\s", re.I)
_OPAQUE_FILE = re.compile(r"prompt[^/\\]*\.(?:enc|encrypted|sealed|age|gpg|pgp)$", re.I)
_OPAQUE_REF = re.compile(r"[\w-]*prompt[\w.-]*\.(?:enc|encrypted|sealed|age|gpg|pgp)\b", re.I)

_TAKES_VALUE = re.compile(r"\bawait\b|\.(?:text|json|content|data|body|read\w*)\b|\bresult\b", re.I)

# --- G215: patch other plugins --------------------------------------------
_PLUGIN_DIR = re.compile(
    r"(?:\.claude|\.codex|\.cursor|\.vscode|\.opencode|\.gemini|\.continue|\.dsh|\.config[/\\][\w.-]+)"
    r"(?:[/\\]+|['\"]\s*,\s*['\"])(?:plugins?|extensions?|skills|hooks|mods)\b|"
    r"\bplugins?[_-]?(?:dir|root|path|folder)\b|\binstalled[_-]?plugins\b|\bother[ _-]plugins?\b",
    re.I)
_MODIFY = re.compile(r"\b(?:patch|monkey|inject|wrap|shim|overwrite|rewrite|tamper|hijack|intercept)\w*", re.I)

# --- G216: instructions aimed at an AI assistant, in docs ------------------
_AI_ADDR = re.compile(
    r"<!--\s*AI[-_ ]?AGENT[-_ ]?(?:START|BEGIN)|"
    r"(?:note|message|instructions?)\s+(?:to|for)\s+(?:the\s+)?(?:ai|llm|assistant|agent)s?\b|"
    r"(?:if|when)\s+you\s+are\s+(?:an?\s+)?(?:ai|llm|language model|assistant|agent)\b|"
    r"\b(?:ai|llm)\s+(?:assistant|agent)s?\s*[:,]|"
    r"(?:paste|send|give|hand)\s+(?:this|the following|the text below)\s+(?:block\s+)?(?:to|into)\s+"
    r"(?:your|the)\s+(?:local\s+)?(?:ai|assistant|agent|claude|codex|chatgpt|cursor|copilot)|"
    r"给\s*AI\s*助手|(?:发给|交给|贴给|粘贴给|转给)[^\n]{0,6}(?:助手|AI|智能体|Agent|Claude|Codex)|"
    r"このまま(?:貼|張|コピー|渡|送)|"
    r"(?<!サブ)(?:AI|エージェント|アシスタント)に(?:そのまま|このまま|全文|下の)[^\n]{0,8}(?:貼|渡|送|読ま)|"
    r"(?<!サブ)(?:AI|エージェント|アシスタント)(?:向け|宛て)の(?:指示|命令|文)",
    re.I)


def _flag(sev: Severity, code: str, msg: str, rel: str, line: int, snippet: str) -> Flag:
    snippet = " ".join(snippet.split())
    snippet = snippet if len(snippet) <= 80 else snippet[:77] + "…"
    return Flag(sev, code, msg, evidence=f"{rel}:{line}: {snippet}")


def _near(a: list[int], b: list[int], win: int = _WIN) -> tuple[int, int] | None:
    """First (a_index, b_index) with |a-b| <= win. Both sorted line indexes."""
    j = 0
    for i in a:
        while j < len(b) and b[j] < i - win:
            j += 1
        if j < len(b) and b[j] <= i + win:
            return i, b[j]
    return None


def _has_near(b: list[int], i: int, win: int = _WIN) -> bool:
    """Is there an entry of the sorted list `b` within `win` of `i`? O(log n)."""
    k = bisect.bisect_left(b, i - win)
    return k < len(b) and b[k] <= i + win


def _hits(lines: list[str], pat: re.Pattern[str], skip=None, comments: bool = True) -> list[int]:
    """Line indexes with a match of `pat`. A match that `skip` also matches at the same
    position is ignored (the rest of the line still counts)."""
    out = []
    for i, ln in enumerate(lines):
        if not comments and _COMMENT.match(ln):
            continue
        if any(not (skip and skip.match(ln, m.start())) for m in pat.finditer(ln)):
            out.append(i)
    return out


def _writes(lines: list[str], suf: str) -> list[int]:
    w = _hits(lines, _WRITE, None, False)
    return sorted(set(w) | set(_hits(lines, _WRITE_SH, None, False))) if suf in _SHELL else w


def _copy_args(line: str, end: int, shell: bool) -> tuple[str, str] | None:
    """(source, destination) of a copy at `end` (shell: where the arguments start; code: where
    the call name starts), or None when they cannot be
    told from this line. Arguments are split at top-level commas (quotes and brackets
    respected), so text after the call on the same line is not read as an argument."""
    if shell:
        seg = re.split(r"\s#", re.split(r"[;&|]", line[end:], maxsplit=1)[0], maxsplit=1)[0]
        if re.search(r"['\"`\\]|\$\(", seg):
            return None  # quoting, escapes or substitution: the words cannot be told apart safely
        toks = [x for x in seg.split() if not x.startswith("-")]
        return (toks[0], toks[-1]) if len(toks) >= 2 else None
    m = re.compile(r"[\w$.]*\s*\(").match(line, end)  # `end` = where the call name starts
    if not m:
        return None
    rest = line[m.end() - 1:]
    args, start, depth, quote, esc = [], 1, 0, "", False
    for i, ch in enumerate(rest[1:], 1):
        if quote:
            esc, quote = (False, quote) if esc else (ch == "\\", "" if ch == quote else quote)
        elif ch in "'\"`":
            quote = ch
        elif rest.startswith(("/*", "//"), i) or ch == "#":
            return None  # a comment inside the call: its commas are not argument breaks
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                args.append(rest[start:i])
                return (args[0], args[1]) if len(args) >= 2 else None
            depth -= 1
        elif ch == "," and depth == 0:
            args.append(rest[start:i])
            start = i + 1
    return None  # the call continues on another line


def _g212(lines: list[str], t: list[int], w: list[int], win: int, shell: bool) -> tuple[Severity, int] | None:
    """A write next to a line naming another package. A copy whose destination is not that
    package (`copyFileSync('node_modules/x/logo.svg', 'dist/logo.svg')`) is not a write into it;
    a copy whose direction cannot be told is MEDIUM."""
    medium = None
    for wi in w:
        near = t[bisect.bisect_left(t, wi - win): bisect.bisect_right(t, wi + win)]
        if not near:
            continue
        ln = lines[wi]
        ms = list(_WRITE.finditer(ln)) + (list(_WRITE_SH.finditer(ln)) if shell else [])
        copies = [m for m in ms if _COPY.search(m.group(0).strip())]
        if not ms or len(copies) < len(ms):
            return Severity.HIGH, wi  # writes, renames, links, sed -i ...: not a copy
        names = {m.group(1) for ti in near if (m := _ASSIGNED.match(lines[ti]))}
        word = re.compile(r"(?<![\w$])(?:" + "|".join(map(re.escape, names)) + r")(?![\w$])") if names else None
        unknown = False
        for c in copies:
            args = _copy_args(ln, c.end() if shell else c.start(), shell)
            if args is None:
                unknown = True
                continue
            src, dst = args
            if _PKG_TARGET.search(dst) or (word and word.search(dst)):
                return Severity.HIGH, wi
            if not (_PKG_TARGET.search(src) or (word and word.search(src))):
                unknown = True  # neither side names the package: direction unknown
        if unknown and medium is None:
            medium = wi
    return (Severity.MEDIUM, medium) if medium is not None else None


def _code_flags(rel: str, lines: list[str], nums: list[int], suf: str) -> list[Flag]:
    flags: list[Flag] = []
    if suf in _CODE:
        t, w = _hits(lines, _PKG_TARGET, _PKG_SKIP, False), _writes(lines, suf)
        # the target and the write sit together (a variable holding the path, then the write);
        # a shell script must name the target on the write line itself
        if (g := _g212(lines, t, w, 0 if suf in _SHELL else 4, suf in _SHELL)):
            sev, wi = g
            bak = _near([wi], _hits(lines, _BACKUP, None, False), 4)
            flags.append(_flag(sev, "G212",
                               ("writes, copies over or renames a file in the same lines that name another "
                                "package (node_modules / site-packages / a resolved module path)"
                                if sev is Severity.HIGH else
                                "copies a file in the same lines that name another package; which side is "
                                "the destination could not be told from the text")
                               + ("; a backup-style name (.bak / .orig) appears next to the write" if bak else ""),
                               rel, nums[wi], lines[wi]))
        # G215: a plugin folder, a patch-style word and a write all within the window of one line
        d, m_, w2 = _hits(lines, _PLUGIN_DIR, None, False), _hits(lines, _MODIFY, None, False), w
        hit = next((i for i in d if _has_near(m_, i) and _has_near(w2, i)), None)
        if hit is not None:
            flags.append(_flag(Severity.MEDIUM, "G215",
                               "names an agent's plugin / extension folder next to a patch-style word and a "
                               "file write", rel, nums[hit], lines[hit]))
    if suf in _CODE | _CONFIG:
        for i in _hits(lines, _REAPPLY, None, False):
            # every match on the line counts: one disabled name must not hide an enabled one
            if any(not _OFF_VALUE.match(lines[i], m.end()) for m in _REAPPLY.finditer(lines[i])):
                flags.append(_flag(Severity.MEDIUM, "G213",
                                   "defines or enables an apply-on-every-start setting or function "
                                   "(autoApplyOnStart and equivalents)",
                                   rel, nums[i], lines[i]))
                break
        sink = _hits(lines, _SINK, None, False)
        # a string that spans lines (triple quotes, an unclosed backquote) cannot be followed line by
        # line: then nothing in the file is unquoted, so a call inside such a string is never hidden
        multiline = any('"""' in x or "'''" in x or x.count("`") % 2 for x in lines)
        if sink:
            # window per kind: a fetch only counts when its result can reach the prompt line
            for pat, what, win in ((_DECRYPT, "a decrypt call", 4), (_BLOB, "a 200+ character encoded string", 4),
                                   (_OPAQUE_REF, "a reference to an encrypted / sealed prompt file", 6),
                                   (_FETCH, "a network fetch", 2)):
                # a call word inside quoted text ("explain how decrypt(x) works") is not a call
                quoted = pat in (_DECRYPT, _FETCH) and suf in _UNQUOTE_SUFFIX and not multiline
                other = _hits([_unquote(x) for x in lines] if quoted else lines, pat, None, False)
                p = None
                if pat is _FETCH:
                    # same line, or any fetch just above when the prompt line takes a value (await / .text
                    # / .json ...). Every candidate counts: one that does not qualify never hides another.
                    same = set(other)
                    for s_ in sink:
                        k = bisect.bisect_left(other, s_ - win)  # first fetch line >= s_-win
                        if s_ in same or (k < len(other) and other[k] < s_ and _TAKES_VALUE.search(lines[s_])):
                            p = (s_,)
                            break
                else:
                    p = _near(sink, other, win)
                if p:
                    flags.append(_flag(Severity.HIGH, "G214",
                                       f"system-prompt / agent-instruction text is set next to {what}; "
                                       f"Zee does not follow the value: read the source to see what text is set",
                                       rel, nums[p[0]], lines[p[0]]))
                    break
    return flags


def _doc_flags(rel: str, lines: list[str], nums: list[int]) -> list[Flag]:
    for i, ln in enumerate(lines):
        if _AI_ADDR.search(ln):
            return [_flag(Severity.MEDIUM, "G216",
                          "documentation contains instructions addressed to an AI assistant",
                          rel, nums[i], ln)]
    return []


def scan_tree(root: Path, paths: list[Path]) -> list[Flag]:
    """Run the tampering checks over the (already enumerated) files. Oversized
    or unreadable files are skipped here: the main pass reports them (G910 / G911)."""
    from . import instructions  # G217-G220 share this pass; imported here because it imports this module

    flags: list[Flag] = []
    seen: set[tuple[str, str]] = set()

    def add(fs: list[Flag], rel: str) -> None:
        for f in fs:
            if (f.code, rel) not in seen:
                seen.add((f.code, rel))
                flags.append(f)

    for p in paths:
        rel = p.relative_to(root).as_posix()
        if _OPAQUE_FILE.search(p.name):
            add([Flag(Severity.HIGH, "G214",
                      "ships a file named like an encrypted / sealed prompt (prompt*.enc / .sealed / .gpg ...); its content is not shown in plain text",
                      evidence=rel)], rel)
        suf = p.suffix.lower()
        if suf not in _CODE | _CONFIG | _DOC and not p.name.startswith("README"):
            continue
        try:
            if p.stat().st_size > _MAX_BYTES:
                continue
            text, _ = textfile.read(p)  # NUL removed; the main pass reports a text file that looks binary
        except (OSError, MemoryError):
            continue
        if text is None:
            continue  # binary (image, archive, executable): outside the text scan, as in the main pass
        lines, nums = [], []
        for n, ln in enumerate(text.splitlines(), 1):
            if len(ln) <= _LONG:
                lines.append(ln)
                nums.append(n)
            else:
                # padding with blanks must not push the write out of range; a long comment stays a comment
                comment = _COMMENT.match(ln)
                ln = re.sub(r"\s{2,}", " ", ln)
                for st in range(0, len(ln), _STEP):
                    lines.append(("//" if comment and st else "") + ln[st:st + _CHUNK])
                    nums.append(n)
        if suf == "" and text.startswith("#!"):  # extensionless script: judge it by its interpreter
            suf = ".js" if "node" in lines[0] else ".py" if "python" in lines[0] else ".sh"
        if suf in _CODE | _CONFIG:
            add(_code_flags(rel, lines, nums, suf), rel)
        if p.suffix.lower() in _DOC or p.name.startswith("README"):
            add(_doc_flags(rel, lines, nums), rel)
        add(instructions.file_flags(rel, p.name, text, lines, nums, suf), rel)
    return flags
