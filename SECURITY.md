# Security Policy

## Reporting a Vulnerability

Zee is an Early Public / Research Project, but it is a security project.
If you find a vulnerability — in the code, in the documentation, in the
threat model, or in the way Zee can be misused — please report it
privately.

**Preferred:** GitHub Security Advisories
→ https://github.com/KAMANOI/zee/security/advisories/new

This creates a private channel between you and the maintainer where the
issue can be triaged before public disclosure.

**Alternative:** if Security Advisories are unavailable to you, contact
Hiroki Kamanoi directly via email (`hirokikamanoi@gmail.com`) with the
subject prefix `[zee-security]`.

## What to include

- A clear description of the issue and why it matters.
- The smallest reproduction you can produce (commands, file paths,
  expected vs. observed behavior).
- The version / commit hash you tested against.
- Optional: your suggested fix or mitigation.

## What to expect

- An acknowledgement within **7 days**.
- An initial assessment (accept / reject / need more info) within **14 days**.
- A coordinated disclosure target of **90 days** from acknowledgement, or
  sooner if a patch lands and we agree on a date together.

## What is in scope

- The Zee codebase under `src/zee/` and `tests/`.
- The MVP behavior (watcher, responder, recovery, notifier, telemetry).
- The decoy seeder templates and the threat model around them.
- The published documentation (README, ARCHITECTURE, STARTER_GUIDE, RESEARCH).

## What is out of scope

- Vulnerabilities in upstream dependencies (Python itself, the
  underlying OS). Please report those to the respective projects.
  (Zee has no third-party runtime dependency; TOML parsing uses the
  standard-library `tomllib`.)
- Misconfiguration in your own environment (allowlist, asset profile,
  webhook URL choice).
- Theoretical attacks against Zee's stated limitations (Zee does not
  prevent intrusion; pointing this out is not a vulnerability, it is the
  honest design boundary).

## Safe Harbor

Good-faith security research that follows this policy will not be the
subject of legal action by the maintainer. Please:

- Avoid privacy violations and destructive testing against systems that
  are not your own.
- Give us a reasonable amount of time to respond before public disclosure.
- Do not use vulnerabilities you discover to access data beyond what is
  necessary to demonstrate the issue.

## Known issues (v0.1)

The following are documented limitations of the v0.1 release that we
have not yet fixed. They are not "vulnerabilities" in the sense of an
unintended weakness — they are honestly-published boundaries of the
current MVP.

- **Canary URL read detection is not wired.** `CanaryTokenRegistry`
  (`src/zee/decoy/canary_token.py`) provides the data structure for
  issuing tokens, but the seeder does not embed canary URLs into the
  decoy files in v0.1. As a result, **read-only attacker activity
  against a macOS / Windows decoy is not observed** (kqueue and
  ReadDirectoryChangesW do not emit read events). Linux observes reads
  directly via `inotify`. Seeder-side canary automation is tracked as a
  separate task.
- **Windows interface enumeration is English-locale-dependent.**
  `list_windows_interfaces()` in `src/zee/responder/cut_full.py` parses
  the English-locale output of `netsh interface show interface`
  (filtering on `cols[0].lower() == "enabled"`). On non-English Windows
  the header text differs and enumeration may return zero entries.
  Locale-independent enumeration (e.g. via `Get-NetAdapter`) is a
  follow-up.
- **`zee restore` on Windows re-enables every interface it can see.**
  The recovery path enumerates all interfaces (not just the ones Zee
  cut) and re-enables them, because Zee does not currently record the
  exact set of interfaces it disabled. If another tool had disabled an
  interface at the same time, `zee restore` will re-enable it as a
  side-effect. Tracking the cut-state per asset is a follow-up.
- **`zee restore` has no authentication.** The MVP is single-operator;
  anyone who can run the CLI can revert containment. See README
  "Limitations" for the threat-model implications.
- **Event log records `decoy_path` in plaintext.** Files are owner-only
  (0700 / 0600), but a root-equivalent attacker can still read them and
  enumerate decoy locations.

These are tracked publicly so that anyone running Zee in v0.1 can plan
around them.
