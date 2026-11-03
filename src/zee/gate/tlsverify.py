"""G230: code or a command that switches off TLS certificate verification.

MEDIUM, "a person confirms": `verify=False` and `curl -k` are everyday
developer shortcuts (local test servers, self-signed lab hosts), so a hit is a
reason to look, not a verdict. Nothing is executed; files are read as text,
one line at a time, comment lines skipped. Files under tests/fixtures/examples
paths are reported as LOW (a test that talks to a local server is the usual
reason; a source can place code there on purpose, so LOW is a rank, not a safety
claim). Documents are not scanned, except a skill's procedure docs (SKILL.md,
commands/, references/ ...): README prose is full of `curl -k` that is
explained, not run, but what a procedure says, the AI does.

Best-effort (invariant I5): verification disabled through a wrapper, a config
key Zee does not know, or a value built at run time is not seen. A clean result
is not a proof that the code checks certificates.
"""

from __future__ import annotations

import re
from pathlib import Path

from . import textfile
from .model import Flag, Severity
from .instructions import _is_procedure
from .tampering import _CHUNK, _CODE, _COMMENT, _LONG, _MAX_BYTES, _STEP, _flag

_OFF = r"(?:false|0|no|off|none)\b"
_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\brejectUnauthorized[\"']?\s*[:=]\s*false\b"), "rejectUnauthorized: false"),
    (re.compile(r"\bNODE_TLS_REJECT_UNAUTHORIZED\b[\"']?\s*[:=,]\s*[\"']?0\b"), "NODE_TLS_REJECT_UNAUTHORIZED=0"),
    (re.compile(r"\bstrictSSL[\"']?\s*:\s*false\b"), "strictSSL: false"),
    (re.compile(r"\bverify\s*=\s*False\b"), "verify=False"),
    (re.compile(r"\b_create_unverified_context\b"), "ssl._create_unverified_context"),
    (re.compile(r"\bcheck_hostname\s*=\s*False\b"), "check_hostname = False"),
    (re.compile(r"\bverify_mode\s*=\s*(?:ssl\.)?CERT_NONE\b"), "verify_mode = CERT_NONE"),
    (re.compile(r"\bPYTHONHTTPSVERIFY\b[\"']?\s*[:=,]\s*[\"']?0\b"), "PYTHONHTTPSVERIFY=0"),
    (re.compile(r"\bInsecureSkipVerify[\"']?\s*:\s*true\b"), "InsecureSkipVerify: true"),
    (re.compile(r"\bwget\b[^\n|;&]*--no-check-certificate\b"), "wget --no-check-certificate"),
    (re.compile(r"\bhttp\.sslVerify\s+" + _OFF + r"|\bGIT_SSL_NO_VERIFY\s*=\s*[\"']?(?:1|true|yes)\b", re.I), "git sslVerify off"),
    (re.compile(r"\bstrict-ssl\s*[= ]\s*false\b"), "npm strict-ssl false"),
]
# curl options that take a value: the next word (or the glued rest, -XPOST) is that value, not a flag.
_CURL_ARG_SHORT = set("oHdXuAebcmwTFxEKryYzCDPQUt")
_CURL_ARG_LONG = {
    "--output", "--header", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--request",
    "--user", "--user-agent", "--referer", "--cookie", "--cookie-jar", "--max-time", "--write-out",
    "--upload-file", "--form", "--proxy", "--cert", "--key", "--cacert", "--capath", "--config",
    "--range", "--retry", "--connect-timeout", "--url", "--resolve", "--dump-header", "--json",
}
_CURL_CMD = re.compile(r"\bcurl\b([^\n|;&]*)")


def _curl_insecure(ln: str) -> bool:
    """`-k` / `--insecure` used as a curl flag (a word that is the value of -o, -H ... is not)."""
    for m in _CURL_CMD.finditer(ln):
        skip = False
        for tok in m.group(1).split():
            tok = tok.strip("\"'")
            if skip:
                skip = False
            elif tok == "--insecure":
                return True
            elif tok.startswith("--"):
                skip = tok in _CURL_ARG_LONG
            elif tok.startswith("-") and len(tok) > 1:
                for j, c in enumerate(tok[1:], 1):
                    if c == "k":
                        return True
                    if c in _CURL_ARG_SHORT:
                        skip = j == len(tok) - 1
                        break
    return False


_TEST_DIR = re.compile(
    r"(?:^|/)(?:tests?|__tests__|spec|fixtures?|examples?|samples?|demo)(?:/|$)"
    r"|(?:^|/)(?:test_[^/]*|[^/]*_test\.\w+|[^/]*\.(?:test|spec)\.\w+)$",
    re.I,
)


# `verify=False` / `check_hostname = False` are also plain words in numpy / pandas
# (measured: 230 of 271 hits in 99,837 files were such). They count only in a file
# that also talks about the network. The other patterns name TLS themselves.
_GENERIC = {"verify=False"}
_NET = re.compile(r"https?|request|session|\burl|cert|ssl|tls|fetch|client|urlopen|\.(?:get|post)\(", re.I)
_NEAR = 3  # lines on each side


def scan_file(rel: str, text: str) -> Flag | None:
    """First hit in `text`, or None."""
    sev = Severity.LOW if _TEST_DIR.search(rel.lower()) else Severity.MEDIUM
    lines = text.splitlines()
    for i, full in enumerate(lines):
        if _COMMENT.match(full):
            continue
        # A minified line is read in overlapping pieces: nothing is skipped.
        pieces = [full] if len(full) <= _LONG else [full[a:a + _CHUNK] for a in range(0, len(full), _STEP)]
        for ln in pieces:
            hits = [w for pat, w in _PATTERNS if pat.search(ln)]
            if _curl_insecure(ln):
                hits.append("curl -k / --insecure")
            for what in hits:
                if what in _GENERIC and not _NET.search("\n".join(lines[max(0, i - _NEAR):i + _NEAR + 1])):
                    continue
                return _flag(
                    sev, "G230",
                    f"turns off TLS certificate verification ({what}); "
                    "a person should confirm the target is local or trusted",
                    rel, i + 1, ln,
                )
    return None


def scan_tree(root: Path, paths: list[Path]) -> list[Flag]:
    flags: list[Flag] = []
    for p in paths:
        suf = p.suffix.lower()
        # A skill's own procedure docs (SKILL.md, commands/ ...) are what the AI runs.
        if suf not in _CODE | {".go"} and not (suf == ".md" and _is_procedure(p.relative_to(root).as_posix())):
            continue
        try:
            if p.stat().st_size > _MAX_BYTES:
                continue
            text, _ = textfile.read(p)
        except (OSError, MemoryError):
            continue
        if text:
            f = scan_file(p.relative_to(root).as_posix(), text)
            if f:
                flags.append(f)
    return flags
