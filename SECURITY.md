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

- Vulnerabilities in upstream dependencies (PyYAML, Python itself, the
  underlying OS). Please report those to the respective projects.
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
