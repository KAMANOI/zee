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
      - uses: KAMANOI/zee@main          # or @v0.10.0 once tagged
        with:
          source: .
          fail-on: high                  # high (default) | medium
```

### npm pre-install hook

Add the gate to a package you control so it runs before npm installs it:

```json
{
  "scripts": {
    "preinstall": "npx --yes zee gate add . --kind npm || exit 1"
  }
}
```

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

Supported report formats: **Semgrep JSON** and **SARIF 2.1.0** (Snyk,
CodeQL, and most CI scanners emit SARIF). Imported findings appear as
`G901` flags at a severity mapped from the source tool, so an imported
`error` drives the verdict to HIGH like a native finding.

## Limits (invariant I5)

This is layered risk reduction, not complete detection. Static scanning
can be evaded by obfuscation; the behavioural sandbox contains writes +
network and blocks reads of the real user homes, but a TLS body sent
through a CONNECT tunnel is opaque; `gate audit` is an on-demand
integrity check, not a live process monitor. Use Zee alongside your
existing scanners, not instead of them.
