# Threat model for Zee (for the OSS Scanner)

Zee is a small, dependency-free Python tool (`src/zee/`, Python >= 3.11, MIT) with
two jobs. This file says what each job promises, where untrusted input enters,
how we rate severity, and what to leave alone. It is a definition of the range Zee
protects, not an apology: inside that range, a defect is a real bug and we want
the report.

Status words used by the project: "Early Public / Research Project". Zee does not
claim to prevent intrusion and does not claim a detection rate. Reports that
only point this out are out of scope (see the end of this file).

Authoritative companions in the repository: `SECURITY.md` (scope and "Honesty
boundaries"), `docs/threat-model.md` (entry gate and distribution),
`docs/gate.md` (gate behaviour and exit codes), `ARCHITECTURE.en.md`.

## What the project does

1. **Post-intrusion detection and containment (exit side).** `zee watch` places
   decoy files and watches them. When an attacker who is already on the host
   changes a decoy (write / delete / rename / extend), the responder can cut the
   host's network (`src/zee/responder/`, `src/zee/egress/`), record evidence, and
   notify the operator. Recovery is manual and needs a restore token
   (`src/zee/recovery/`). Read-only contact with a decoy is notification only; it
   is never cut automatically. Automatic cutting is off unless the operator opts in
   (default `dry_run`).
2. **Pre-install static inspection (entry gate).** `zee gate add <path>` copies a
   third-party AI artifact (skill, MCP server, npm package, PyPI package, VS Code
   extension) into a quarantine directory without running it, inspects it statically
   (`src/zee/gate/`), and returns a verdict (LOW / MEDIUM / HIGH) as the process
   exit code. `zee gate audit` compares pinned artifacts with their recorded hash.
   An opt-in `--behavioral` mode runs an install hook inside a macOS
   `sandbox-exec` profile only; where no isolation backend exists the artifact is
   never executed.
3. **Evidence export and MCP server.** Events are written as a hash-chained
   JSONL log (`src/zee/telemetry/`); `zee` can export a containment report
   (`src/zee/report/`). An optional MCP server (`src/zee/mcp/`, extra `mcp`)
   exposes read tools and propose-only tools. It never cuts, restores or edits
   policy itself.

The entry gate is the most exposed surface: its whole purpose is to process
hostile files from strangers before the user installs them.

## Where untrusted input enters (rank order for your attention)

1. **The artifact under inspection** (the argument of `zee gate add`, GitHub Action
   `source:`): every file name, file content, symlink, archive-like layout,
   manifest (`package.json`, `pyproject.toml`, `setup.py`, `SKILL.md`, MCP
   manifests, VS Code `package.json`), encoding, size and Unicode trick. The
   author is assumed hostile and aware of how Zee works. Relevant code:
   `gate/fetch.py` (copy into quarantine, symlinks preserved not followed),
   `gate/static_checks.py`, `gate/adapters.py`, `gate/scorer.py`,
   `gate/inspector.py`, `gate/denylist.py`, `gate/pins.py`.
2. **Imported third-party scan results** (`--import-scan`: Semgrep JSON and
   SARIF 2.1.0, `gate/imports.py`). The file is attacker-influenced data
   (it can contain text derived from a malicious artifact).
3. **Operator configuration and state files**, parsed from disk:
   `assets.toml`, the config schema (`config/`), the allowlist (`policy/`),
   the cut ledger and event logs (`telemetry/`), pin and denylist files.
   Files that a lower-privileged or earlier-compromised process could have
   edited (including truncated, oversized, wrongly typed or non-UTF-8 content).
4. **Attacker actions against decoys** after intrusion: file operations on
   decoy paths, file names, racing the watcher, symlink swaps on decoy or state
   paths, flooding events, crafted content in decoys, forged canary callbacks.
5. **Canary receivers** (`examples/query_canary_*_receiver.py`; the core has no
   network listener): inbound HTTP/DNS requests are untrusted. The core only
   reads their recorded results.
6. **Privilege-separation daemon socket** (`src/zee/privsep/`, off by default,
   Unix socket; the business user can ask for "cut" and "status" and can open an
   approval request (`challenge`/`submit`); restore, configuration change and stop
   need an approver signature): any bytes a local
   user can send.
7. **MCP clients** (`src/zee/mcp/`): tool arguments (`asset_id`, `event_id`,
   `since`, justification text) come from an AI agent that may itself be
   manipulated.
8. **Environment and command output Zee parses:** `iptables`/`nft`/`pfctl`/
   `netsh`/PowerShell read-back text, `ZEE_*` environment variables.

## Components that matter most

Highest value (a defect here defeats the product's promise):

- Entry-gate verdict logic: `gate/static_checks.py`, `gate/scorer.py`,
  `gate/inspector.py`, exit-code mapping in `cli.py`, `gate/denylist.py`,
  `gate/pins.py`, `gate/audit.py`, quarantine copy in `gate/fetch.py`.
- Containment: `responder/*`, `egress/*` (including signing and read-back
  verification), `recovery/*` (restore token and cut-record checks).
- Evidence integrity: `telemetry/events_log.py` (hash chain, rotation, `verify_chain`),
  `telemetry/cut_state.py`, `report/*`.
- Privilege separation: `privsep/*`.

Important but second:

- `mcp/*`, `notifier/*` (webhook/local), `policy/*`, `config/*`, `decoy/*`,
  `watcher/*`, `doctor.py`.

Low value / lenient review:

- `src/zee/dilution/` (generator of dummy personal-data records, file output
  only: a fictional-town layer and a layer based on real non-residential
  addresses; the dummy data itself is not a finding, but a defect in how the
  generator reads or writes files is), `docs/`, `examples/` (demo and receiver samples; real
  deployments run their own receiver), `tests/`.

## How to exercise it

- `pip install -e ".[test,mcp]"` is already done in the image; `pytest tests/ -q`
  runs the full suite offline (about 1,000 tests; a few are skipped by OS).
- Entry gate against any directory: `zee gate add <dir> --kind skill|mcp|npm|pypi|vscode|package --json`.
  Exit code is the verdict: `0` LOW, `1` MEDIUM, `2` HIGH, `3` verdict exists but
  part of the artifact was not inspected, `4` no verdict. `--json` separates
  `inspection.status` (`complete` / `partial` / `error`) from `risk_level`.
  Use a private `HOME` and quarantine directory when you experiment.
- Evidence log: write events through the public API in `telemetry/events_log.py`,
  then call `verify_chain`.
- Everything that touches the network stack (`zee cut`, `zee restore`,
  `cut_egress`, the privsep daemon) changes the machine you run it on.
  `dry_run` applies to automatic cutting only: **`zee restore` has no dry-run**
  and performs the real recovery after authentication. **Do not run a real cut or
  any `zee restore` on the scanning VM:** it would change or cut your own
  channel. Exercise these paths by replacing the OS command layer with the
  fakes the existing tests use, or by reading the code. A finding that needs a
  live cut to show is acceptable if the logic error is clear from the code and a
  test can demonstrate it with those fakes.
- Linux, macOS and Windows code paths exist. Only the Linux paths can be run in
  the scanner image; findings about macOS (`pf`, `sandbox-exec`, `osascript`) or
  Windows (`netsh`, PowerShell) are welcome as code-reading findings, marked as
  such.

## How we rate severity

Critical:

- An artifact that is clearly malicious by Zee's own rules (credential theft,
  exfiltration, persistence, remote download-and-execute, destructive command)
  receives LOW **and** `inspection.status == "complete"` through a generic,
  low-effort transformation (fail-open of the gate), or can make the gate
  return exit `0`.
- Executing, importing, or otherwise running content from the artifact under
  inspection during the static inspection (`zee gate add` without
  `--behavioral`), or escaping the quarantine directory (path traversal, symlink
  following, writing outside quarantine or reading host files into the verdict).
- With `--behavioral`: running the artifact outside the sandbox profile, or
  reaching host files and network the profile is meant to deny. Running the
  install hook inside the profile, in its working copy under the isolated HOME,
  is the designed behaviour and not a finding.
- Arbitrary code execution anywhere in the core from attacker-controlled input
  (unsafe `eval`/`pickle`/`yaml.load`, shell injection through a file name or a
  manifest value).
- Privilege escalation through the privsep daemon: an operation that needs the
  approver signature (restore, configuration change, stop) being **executed**
  without a valid signature, or a root-run command taking attacker-chosen paths
  or code. Creating an approval request (`challenge`) without a signature is
  by design and is not an escalation.

High:

- A containment defeat that does not need root: making the watcher miss a
  change-class contact with a decoy, disabling automatic containment, or
  suppressing the response without being recorded; an ordinary `zee restore`
  that succeeds without a well-formed cut record (Z605) or without the restore
  token. The explicit emergency path `--all-interfaces` is documented to work
  without a ledger and is not a bypass.
- Tampering with the hash-chained evidence that `verify_chain` reports as
  clean, within what the chain promises: an edit of a record's content, a
  deletion of a record in the middle, or a reorder (including across rotated
  segments). The chain is an unkeyed hash: cutting the tail off, and recomputing
  the whole chain after an edit, are documented as not detected
  (`telemetry/events_log.py`, `tests/test_events_log_chain.py`); do not report
  those.
- The gate returning exit `0` for an artifact whose inspection was incomplete
  (oversized text, malformed manifest, unreadable file, failed import) instead of
  `3`/`4`; a crash path that returns `0`.
- Denylist or pin bypass (a pinned artifact whose content changed is reported
  clean by `gate audit`; a denylisted hash is accepted).
- Verdict downgrade by Unicode/encoding tricks for known detectors (G-codes) that
  the documentation says are covered: a fixed concrete payload listed in
  `docs/gate.md` or `docs/threat-list.md` is missed after a trivial
  transformation the documentation claims is normalised.
- Secrets leaking into logs, notifications, MCP output or exported reports
  (restore token, canary URL secret, webhook URL), or MCP tools performing an
  action that the documentation says is propose-only.
- Egress-rule bugs that leave more open than `SECURITY.md` documents for the
  chosen cut method.

Medium:

- Denial of service from attacker-controlled input that makes the gate, watcher
  or daemon hang or exhaust memory/disk (unbounded recursion, regex backtracking,
  event flooding), when a bounded and cheap input does it. Gate slowdowns that
  need very large inputs are Low.
- Race conditions (time-of-check/time-of-use) that need a same-user attacker and
  only degrade detection.
- Crashes (uncaught exceptions) on malformed configuration, state or imported
  report files that stop the tool but fail closed (non-zero exit, no verdict).
- Incorrect read-back/verification that reports a cut or restore as confirmed
  when it is not.

Low / informational:

- False positives and false negatives of heuristic detectors that the
  documentation already lists as limits (see below), error-message wording,
  unreachable code, style.
- Findings that require the attacker to already control the Zee state directory
  as the same user and root-equivalent control, unless the documentation promises
  protection against that position.

A single concrete reproduction beats a long argument. Rate severity by impact,
and state separately how well it is confirmed: reproduced, shown by a test with
the existing fakes, or established by reading the code only (name the code that
makes it true and the conditions needed). Do not lower the severity just because
the platform could not be run in the scanner image; say "unconfirmed" instead.

## Not vulnerabilities (leave alone)

These are the published boundaries of the product (`SECURITY.md`, "Honesty
boundaries"; `docs/gate.md`, "Limits"). They describe what Zee is, and reports that
only restate them are not useful:

- Zee does not prevent intrusion and is not a firewall, IDS/IPS or EDR. It does
  not guard the network boundary.
- Read-only contact with a decoy is notification only and not cut automatically.
- Without the optional privsep daemon (a prototype, off by default), a same-user
  attacker can stop the watcher, read `~/.zee/restore_token` and edit the policy.
  With it, the watcher and the user's own files still run as the business user
  (a same-user attacker can still stop the watcher; the privsep tamper check
  observes that, it does not forbid it); privsep separates the root-owned cut
  path, the approved configuration and the restore operation. A root-equivalent
  attacker is never in scope for protection. Report privsep bypasses, not the
  absence of privsep.
- The entry gate is static and heuristic. It does not detect all malicious
  artifacts, does not maintain a CVE database, and its prompt-injection check
  (G501) knows a fixed phrase list; paraphrases and instructions inside images
  or encoded blobs are known misses. Do not report "a new paraphrase evades G501"
  or "this obfuscation evades the static scan" unless the documentation claims
  that case is handled. Do report crashes, fail-open handling, and cases that
  the documentation says are normalised.
- `--behavioral` is available only through macOS `sandbox-exec`; Linux and Windows
  skip execution by design. TLS bodies inside a CONNECT tunnel are opaque.
- What `cut_egress` leaves open (private ranges, loopback, link-local/ULA on some
  paths, VPN/overlay traffic on private addresses, pre-existing connections on
  macOS/Windows) is documented per path in `SECURITY.md`. Report deviations from
  the documented behaviour only.
- Windows behaviour not yet tested on real hardware; POSIX permission checks are
  skipped on Windows by design.
- Third-party code outside `src/zee/` and `tests/` (Python, the OS, the `mcp` SDK
  and its dependencies) belongs to its own project. If Zee uses such an API
  unsafely, report that part.
- `examples/` receivers are samples. The README tells operators to run their own;
  hardening a sample is Low.
- The content of the deliberately dummy records produced by `src/zee/dilution/`
  (as opposed to defects in how the generator handles files and input).
- Misconfiguration in the operator's environment (allowlist, asset profile,
  webhook URL choice).

## Report and patch format we want

- One finding per report. Title: component, defect, impact.
- Severity using the scale above, with one sentence of reasoning.
- Smallest reproduction: exact commands or a failing `pytest` test (we use plain
  `pytest`; tests isolate `HOME`, so look at `tests/conftest.py` first), the
  expected result and the observed result, the Zee version / commit.
- Where the guarantee is stated (file and line of the documentation or code
  comment) and which input breaks it. For gate defects name the G-code involved.
- A proposed patch as a unified diff against `main` that keeps the project's
  conventions: standard library only (no new runtime dependency), a regression
  test next to the existing ones in `tests/`, behaviour on invalid input is
  fail-closed (non-zero exit, no verdict) never LOW.
- Do not include working exploit payloads for third-party products. Fictional
  example artifacts are fine.

## Duplicates

Treat two reports as one if they share the root cause (the same missing check in
the same function), even when different inputs reach it. Report the root cause
once and list the affected entry points. Different G-codes or different
platforms' implementations of the same idea (for example `pf` and `nft` paths)
are separate findings only if each needs its own fix.

## Contact and handling

Reports go to the maintainer (`SECURITY.md`: GitHub Security Advisories, or the
`[zee-security]` email address). Findings from this scanner are treated as
confidential until a fix ships or the maintainer decides on disclosure.
