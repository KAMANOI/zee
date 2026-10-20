# Zee entry gate — CI, pre-install, and interoperability

The entry gate inspects an AI artifact **before** it reaches your real
environment. It runs entirely on your machine — no server, no account.

```
zee gate add <path> [--kind skill|mcp|npm|pypi|vscode|package]
```

It fetches the artifact into a quarantine directory **without running it**,
statically inspects it, and prints a `LOW` / `MEDIUM` / `HIGH` verdict.
The **exit code is the verdict** (`LOW=0`, `MEDIUM=1`, `HIGH=2`), so it
composes anywhere a non-zero exit fails the step.

Two more codes mean the gate could not vouch for the artifact:

| Exit | Meaning |
|---|---|
| `3` | A verdict exists, but part of the artifact was **not inspected**: a text file over 2 MiB, a text-typed file containing NUL bytes, a malformed manifest, a `--import-scan` file that could not be read, or `--behavioral` was requested but no isolation backend ran it. Never passes, even at LOW. |
| `4` | **No verdict**: the inspection failed (missing source, unreadable file, internal error, promotion failed). |

One rule decides "text or binary" for every check (main pass and G205-G220, `src/zee/gate/textfile.py`),
on the raw bytes of the first 8 KiB. No NUL byte there: text. A file chosen by its name (Dockerfile*,
Makefile, README*, dotfiles such as `.bashrc` / `.env`) or starting with `#!`: text, whatever it holds. A NUL in
a file whose suffix any check reads as text (`.py` `.js` `.jsx` `.ts` `.tsx` `.sh` `.json` `.yaml` `.md` `.html`
...): the file is still scanned, and it is also reported as G911 (not inspected), because it looks binary and
the result may be incomplete. Anything else with a NUL (images, archives) is binary: outside the text scan and not counted as a gap. There
is no exception by file content (macOS `.DS_Store` / `._*` are dotfiles and are read as text: a magic number
is as attacker-written as the rest of the file). Every text
file is read with its NUL bytes removed (anywhere in the file), so a NUL does not switch a check off; a Python
file that still does not parse after that is reported as G911. A UTF-16 text file (NUL in every other byte)
is therefore G911 with a text suffix and binary without one: Zee reads UTF-8 only. Text files are scanned
whatever their extension.

Text quoted from the artifact (file and server names, manifest name, version, capabilities, install hooks,
flag evidence, imported scanner results, notes) is stored as it is. `--json` is ASCII-only: every
non-ASCII character (C1 controls, U+202E, U+200B, and also Japanese text) and every control character is a
`\uXXXX` escape, so the JSON cannot rewrite a terminal and a JSON parser gives the real path back. In the terminal output (the verdict, `zee
gate audit`, promotion and error messages) control and other invisible characters are shown as visible
escapes (`\x1b`, `\u200b`), and a backslash that would read as such an escape is doubled (`\\x0a` is the four
characters, `\x0a` a line feed), so two different names never look the same.

`--json` reports the two axes separately: `inspection.status`
(`complete` / `partial` / `error`, with `inspection.gaps` listing what was
skipped) and `risk_level`. A LOW verdict is promoted (`--promote-to`) only
when the inspection is `complete`.

## Prompt-injection text (G501)

G501 flags instructions aimed at the AI agent that will read the artifact
(SKILL.md, MCP tool descriptions, READMEs, any text file). It has two tiers:

| Tier | Severity | What fires it |
|---|---|---|
| Known phrase | HIGH | A known phrase (`ignore all previous instructions`, `you are now`, …) in the raw text **or** in a normalized view: NFKC (full-width → ASCII), every Unicode format character (Cf: zero-width, soft hyphen, ZWJ, bidi marks) plus other invisibles (CGJ, variation selectors, Hangul fillers) removed, common Cyrillic/Greek look-alikes folded to Latin, Markdown emphasis removed, whitespace collapsed. |
| Context rule | MEDIUM | A paraphrase: two *different* cues within about 400 characters of each other (blank lines do not separate them) — earlier instructions declared void, a claim to take priority, keeping *this instruction/replacement* hidden, replacing the *requested* answer. English and Japanese. A single cue never fires; a cue negated in a simple way (`is not obsolete`, `does not take priority`, `無視しないで`, `無視することは禁止`, `最優先にしないで`) does not count, while `not merely / not only / not just` is treated as emphasis, not negation. |

The context rule is an estimate, so each of its flags is MEDIUM. A flag
blocks `--promote-to`; on its own it passes the default `fail-on: high`,
but several such flags (e.g. the same text in multiple files) or other
findings can add up to a HIGH verdict. **Use `fail-on: medium` if any
paraphrased injection should fail CI.** Quoting a
payload or adding words such as "payload" does not lower either tier.

## Agent tool and sandbox configuration (G205–G211, G602)

Some artifacts are not malicious but show an unsafe way to wire an agent's
tools or containment, and copying them copies the weakness. These checks read
the configuration; they never run it.

| Code | Severity | What it flags |
|---|---|---|
| G205 | MEDIUM | A value interpolated into a shell command string without quoting (f-string, `.format`, `%`, `+`; JS template literal) that reaches `os.system`, `shell=True`, `create_subprocess_shell` or a helper that calls them. `shlex.quote` (and `shellquote`-style names), `int()` / `float()`, `{x:d}` and constants are not flagged; a type hint such as `x: int` is not treated as proof. |
| G206 | LOW | A tool named `computer` / `browser` declared with a custom `input_schema` and no vendor tool type (`computer_20…`): the API's screen-specific safety classifiers do not apply to a custom definition. |
| G207 | LOW | A Python tool class whose literal `input_schema` and handler (`execute` / `__call__` / `run` …) parameters disagree: a declared property the handler does not accept, a handler parameter the schema never offers, or a parameter optional in the schema but required by the handler. Handlers with `**kwargs`, or a single parameter that unpacks the whole input, are skipped. |
| G208 | MEDIUM | A command allowlist (Python / JS names containing `allow`, or Claude `permissions.allow` `Bash(...)` rules) that includes `bash`, `sh`, `python`, `node`, `env`, `sudo`, a single `*.sh` script, or an inline-code form (`node -e`, `python -c`). The agent can write the script or the code. |
| G209 | MEDIUM | A network policy (YAML / JSON / TOML that mentions endpoints / egress / allowed hosts) in `audit` / log-only mode, `enforce: false`, a wildcard host, or a path rule that allows every path. A wildcard *inside* a path (`/work/*/heartbeat`) is not flagged. |
| G210 | MEDIUM | `NOPASSWD` sudo rules. |
| G211 | MEDIUM | `x11vnc` started without a password option, or `-nopw` / `-SecurityTypes None`. Package-install lines are not flagged. |
| G602 | MEDIUM | `cat` / `head` / `grep` (without `-q` / `-c` / `-l`) or "read/print the …" on `.env`, `.aws/credentials`, `.ssh/id_*`, `.npmrc`, `.pypirc`, `.netrc`. Lines that say *never / do not / without*, public keys (`id_*.pub`) and `.env.example` / `.sample` / `.template` are not flagged. |

Limits, stated plainly: these are heuristics, one flag per code per file. Files over 2 MiB get G910 from the main pass; a Python file too deeply nested to walk gets G911. The line patterns are easy to evade on purpose (renamed variables, split expressions, unusual layout); they find the common honest mistakes, not a determined author.
Python files are parsed one at a time (only a summary of each file's functions is kept); a file too deep or too large to parse, or text beyond 256 MiB for the whole tree, gets G911 (the inspection becomes `partial`, never a silent pass). Data flow across files is followed by function name only (calls on `subprocess` / `asyncio` / `os` and similar standard modules are not matched to a same-named helper); only the first positional argument of a shell call is read, so a command passed as a keyword (`subprocess.run(args=..., shell=True)`) is not seen; a value validated
in a place Zee cannot follow is still reported; JS/TS handler signatures are
not compared (G207), and schemas that are not literals are skipped. A clean
result does not mean the configuration is safe.

## Tampering plugins (G212–G216)

A plugin can be harmless to read and still change the host it is installed
on: it overwrites another vendor's package, re-applies itself on every start,
and injects a prompt text the installer cannot read. These checks look for
that shape. They read files; they never run them.

| Code | Severity | What it flags |
|---|---|---|
| G212 | HIGH | Code that writes, copies over, renames or links a file within 4 lines of a line that names another package (`node_modules`, `site-packages`, a `require.resolve` path); in shell scripts, on the same line. The message adds "backup-style name" when a `.bak` / `.orig` / `.backup` name sits next to the write. A `node_modules/.cache`-style path is skipped (only that path, not the rest of the line). A copy is judged by direction (its second argument): copying *out of* a package (`copyFileSync('node_modules/x/logo.svg', 'dist/logo.svg')`) is not flagged, copying into one is HIGH, and a copy whose destination cannot be told from the text is MEDIUM: both sides are variables not set on the nearby lines, the call spans lines or has a comment between its arguments, or a shell `cp` uses quoting, escapes or `$(...)`. |
| G213 | MEDIUM | A setting or function named like "apply on every start" (`autoApplyOnStart`, `reapply_on_launch`, `autoReapply` …) that is not set to false right after the name. A function with that name is flagged whether or not it is called: Zee does not follow calls. |
| G214 | HIGH | System-prompt / agent-instruction text set within a few lines of a decrypt call, a 200+ character encoded string, a reference to an `*.enc` / `*.sealed` / `*.gpg` prompt file, or a network fetch (same line, or up to 2 lines above while the prompt line takes a value such as `await` / `.text`). A shipped file named like `prompt*.enc` also counts. Zee reports what sits next to what; it does not decrypt or follow the data, so a person must open the source to see what text is set. In JS / Python, words inside plain quoted text ("explain how decrypt(x) works") are not counted as calls. A string that can run code (a template literal containing `${`, an f-string containing `{`) is read whole, so plain text inside it, text in a template literal that spans lines, and an escaped `\${` can still be flagged. A line holding `${`, an f-string prefix or triple quotes is read whole for the same reason. A file in which any line contains triple quotes or an odd number of backquotes is not unquoted at all (Zee does not parse whether these really open a string that spans lines; this may flag more plain text). Shell and config lines are read as they are (in shell a backquote or `$(...)` runs a command; a config file runs nothing, but its text is not unquoted either), so a config value such as `"system_prompt": "Explain how decrypt(data) works."` is flagged HIGH. A plain prompt next to an unrelated fetch can be flagged, and an agent that loads its system prompt over the network at run time is flagged HIGH by design. |
| G215 | MEDIUM | Code that names an agent's plugin / extension / skills folder (`.claude/plugins`, `.vscode/extensions`, …) within the window of a patch-style word (`patch`, `wrap`, `inject`, `shim`, `overwrite` …) and a file write. A plain installer copying its own files is not flagged; an updater of the plugin's own files that uses those words can be. |
| G216 | MEDIUM | Documentation addressed to an AI assistant ("paste this to your assistant", `<!-- AI-AGENT-START -->`, "このまま貼れば", "给 AI 助手"). Zee only warns; whether the assistant may act on it is decided by the operator's own rules. |

G212 and G214 are HIGH (blocked at the default `fail-on: high`; a G212 copy of unknown direction is MEDIUM). G213, G215 and
G216 are MEDIUM (a person reads them). Tools that patch `node_modules` on
purpose (patch-package style) are flagged G212 by design.

Limits, stated plainly: line patterns, one flag per code per file. A renamed
variable, a path built in pieces more than 4 lines apart, a prompt fetched
under another name, or a payload in a non-text file passes. Files over 2 MiB
get G910 from the main pass. A line over 2,000 characters (minified code) is read
in overlapping 600-character pieces after runs of blanks are collapsed, so "near"
means within about 1,200 characters there; padding with other filler is not handled. Comment lines are not read by the code checks (G212–G215).
A clean result
does not mean the plugin is safe.

## Procedures that change the AI's own setup (G217–G220)

Some risk sits in the wording of a skill, not in its code: a reference file
that tells the assistant "register this server" or "merge this key into
`~/.cursor/mcp.json`". These checks make that visible before install. All four
are MEDIUM, the same tier as G213 / G215 / G216: on its own a MEDIUM flag passes
the default `fail-on: high`, but it blocks `--promote-to` (only a LOW verdict
is installed), and MEDIUM flags add up (weight 4 each; 10 or more is HIGH), so
a tree with three of them is HIGH. They read files; they never run them, and
they do not say anyone acted in bad faith.

| Code | Severity | What it flags |
|---|---|---|
| G217 | MEDIUM | A procedure document (`SKILL.md`, anything under `skills/`, `references/`, `commands/`, `agents/`, `prompts/`, or `AGENTS.md` / `CLAUDE.md` / `GEMINI.md`) with an MCP word, a registering verb (register, add, connect, configure, `mcp add` ...) and a non-local http(s) URL within 12 lines. A verb inside a same-line negation ("never add ...") is not counted. |
| G218 | MEDIUM | The same kind of document naming an AI-tool or developer-tool config file (`mcp.json`, `.claude/settings.json`, `.codex/config.toml`, `.cursor/rules`, `CLAUDE.md`, `AGENTS.md`, shell profiles ...) with a writing verb (merge, append, add, write, edit, create ...) on that line or the next two. README files and anything under `docs/` are not read by G217 / G218, wherever they sit: they are written for people. |
| G219 | MEDIUM | A plugin / MCP definition (a JSON or TOML file whose name contains mcp, plugin, marketplace, settings or config) with an MCP server entry whose URL is a non-local http(s) address; the message names the server and the host. A plugin that only points at another file (`"mcpServers": "./.mcp.json"`) is not flagged itself; the file it points at is. |
| G220 | MEDIUM | Code or config that starts a browser with `--no-sandbox`, `--disable-setuid-sandbox`, `--disable-web-security`, `--disable-site-isolation-trials`, `chromiumSandbox: false` / `chromium_sandbox=False`. Comment lines are not read. |

Limits, stated plainly: line patterns, one flag per code per file. A
registration described in other words or another language, a config path built
from pieces, a connection declared in a format Zee does not parse, or a
command-based (stdio) server is not seen. A negation on another line is not
understood. Zee does not follow a connection into the application code (for
example a sign-in or upload path inside an editor): the flags say where the
files declare it, not what the program sends. A clean result does not mean the
plugin is local-only.

## Use it as a pre-install / CI check

### GitHub Action

```yaml
# .github/workflows/zee.yml
name: Zee gate
on: [pull_request]
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: KAMANOI/zee@v0.16.0       # or pin to a commit SHA
        with:
          source: .
          fail-on: high                  # high (default) | medium — medium also fails G501 paraphrases
```

### npm pre-install hook

Add the gate to a package you control so it runs before npm installs it:

```json
{
  "scripts": {
    "preinstall": "zee gate add . --kind npm || exit 1"
  }
}
```

> **Do not run `npx zee` or `pip install zee`.** Those names on npm and PyPI belong to
> unrelated packages by other authors (verified 2026-09-05). Zee is installed from this
> repository only — see the install instructions in the README, and note that the
> preinstall hook above assumes `zee` is already on PATH from that install. Running the
> wrong `zee` is exactly the supply-chain problem this gate exists to catch.

### pip / Python projects

pip has no consumer-side pre-install hook, so gate **before** you install
in CI:

```bash
zee gate add ./vendor/some-package --kind pypi && pip install ./vendor/some-package
```

## Catch a Rug Pull after install (Phase 3)

Promote a vetted artifact and Zee pins its hash:

```bash
zee gate add ./skill --kind skill --promote-to ~/.claude/skills
```

Later, re-check every pinned artifact for a silent self-update / rewrite:

```bash
zee gate audit            # clean=0, missing=1, drifted(=Rug Pull)=2
zee gate audit --rescan   # also re-inspect what a drifted artifact became
```

A drifted artifact's new hash is added to your local denylist, so
re-installing that exact version is blocked everywhere the gate runs.

## Run the artifact in a sandbox (Phase 2, opt-in)

```bash
zee gate add ./skill --kind skill --behavioral
```

Detonates the artifact's install hook inside an isolation sandbox (macOS
`sandbox-exec` today) and watches for credential exfil, persistence, and
outbound traffic. If no isolation backend is available the artifact is
**never** run on the bare host — the run is skipped and the static
verdict stands.

## Interoperate, don't duplicate (invariant I4)

Zee does not re-implement Semgrep / Snyk / Socket. Fold their output into
the same verdict:

```bash
semgrep --json -o semgrep.json ./pkg
zee gate add ./pkg --kind npm --import-scan semgrep.json
```

Supported report formats: **Semgrep JSON** and **SARIF 2.1.0**. Imported
findings appear as `G901` flags at a severity mapped from the source tool, so
an imported `error` drives the verdict to HIGH like a native finding.

## Using Zee with Snyk / Socket / Semgrep

**Verified:** Zee imports Semgrep JSON and SARIF 2.1.0 through
`--import-scan`. An imported `error` becomes a HIGH-severity `G901` finding.
Zee separately applies its own checks for prompt-injection text aimed at
Claude skills or MCP artifacts, excessive permission requests, and Rug Pull
drift.

**Unverified:** Snyk CLI is reported to offer SARIF output. If
`snyk code test --sarif-file-output=snyk.sarif` produces a SARIF report, pass
it to `--import-scan snyk.sarif` (unverified in this repo).

**No information:** This repository has no verified information about whether
Socket emits SARIF. If it does not, review Socket's verdict first and then use
Zee for Zee-specific checks only.

Division of responsibility: use Snyk or Socket for known dependency
vulnerabilities, Semgrep for static code patterns, and Zee for instructions in
AI artifacts, permission requests, and post-distribution changes. Zee does not
replace those tools (invariant I4).

## Limits (invariant I5)

- **G501 paraphrase detection does not generalize.** In a blind test (10
  injection samples written without sight of the rule), 0.12.0 flagged 0 of
  10. The context rule only knows a fixed list of words; reworded
  instructions in English or Japanese pass as LOW. A tutorial that quotes
  attack phrases can score MEDIUM (false positive). Treat G501 as a filter
  for known and lightly disguised phrases, not as protection against
  injection in general.

This is layered risk reduction, not complete detection. Static scanning
can be evaded by obfuscation; the behavioural sandbox contains writes +
network and blocks reads of the real user homes, but a TLS body sent
through a CONNECT tunnel is opaque; `gate audit` is an on-demand
integrity check, not a live process monitor. Use Zee alongside your
existing scanners, not instead of them.

G501 specifically: the context-rule vocabulary is a fixed list, so a
paraphrase outside it, or cues spread more than ~400 characters apart,
is missed. Split spellings (`I.g.n.o.r.e`, `ig-nore`), accented letters or
combining marks inside a word (`Ìgnore`), look-alikes outside the folding
table, and instructions in images or encoded blobs are not
read. Negation handling is shallow: double negatives ("never fail to
ignore…", "無視しないわけにはいかない") are not resolved — they are treated
as negated. Teaching material that paraphrases an attack scores MEDIUM like
the attack itself; one that quotes a known phrase verbatim scores HIGH.
