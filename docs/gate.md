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
| `3` | A verdict exists, but part of the artifact was **not inspected**: a text file over 2 MiB, a malformed manifest, a `--import-scan` file that could not be read, or `--behavioral` was requested but no isolation backend ran it. Never passes, even at LOW. |
| `4` | **No verdict**: the inspection failed (missing source, unreadable file, internal error, promotion failed). |

Binary files (images, archives: anything containing NUL bytes) are outside the
text scan and are not counted as gaps. Text files are scanned whatever their
extension.

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
| Context rule | MEDIUM | A paraphrase: two *different* cues within about 400 characters of each other (blank lines do not separate them) — earlier instructions declared void, a claim to take priority, keeping *this instruction/replacement* hidden, replacing the *requested* answer. English and Japanese. A single cue never fires; a negated cue (`is not obsolete`, `無視しないで`, `無視することは禁止`) does not count. |

The context rule is an estimate, so it stops at MEDIUM: it blocks
`--promote-to` but passes the default `fail-on: high`. **Use
`fail-on: medium` if paraphrased injection should fail CI.** Quoting a
payload or adding words such as "payload" does not lower either tier.

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
      - uses: KAMANOI/zee@v0.11.0       # or pin to a commit SHA
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

This is layered risk reduction, not complete detection. Static scanning
can be evaded by obfuscation; the behavioural sandbox contains writes +
network and blocks reads of the real user homes, but a TLS body sent
through a CONNECT tunnel is opaque; `gate audit` is an on-demand
integrity check, not a live process monitor. Use Zee alongside your
existing scanners, not instead of them.

G501 specifically: the context-rule vocabulary is a fixed list, so a
paraphrase outside it, or cues spread more than ~400 characters apart,
is missed. Split spellings (`I.g.n.o.r.e`, `ig-nore`), look-alikes outside
the folding table, and instructions in images or encoded blobs are not
read. Negation handling is shallow: double negatives ("never fail to
ignore…", "無視しないわけにはいかない") are not resolved — they are treated
as negated. Teaching material that paraphrases an attack scores MEDIUM like
the attack itself; one that quotes a known phrase verbatim scores HIGH.
