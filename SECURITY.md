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

<a id="shared-vs-private-logs-v05"></a>
## Shared vs. private logs (v0.5+)

Zee runs as a **seeded OSS** (see [CONTRIBUTING.md](./CONTRIBUTING.md))
and explicitly encourages users to share maintenance knowledge in
GitHub Discussions and the Wiki. To avoid confusion about what is
safe to share:

| Artefact | Where | Share? |
|---|---|---|
| Attack detection log (`events.jsonl`, `metrics.jsonl`) | `~/.local/state/zee/` (0600) | **Do not share.** v0.3 already strips `decoy_path`; the `decoy_ref` (`asset_id#index`) it keeps does not leak filesystem layout, but the raw records can still reveal attacker behaviour against your specific assets |
| Canary registry (`canary_tokens.jsonl`) | `~/.local/state/zee/` (0600) | **Do not share.** Carries token IDs against your operator-controlled URL |
| Cut state (`cut_state.jsonl`) | `~/.local/state/zee/` (0600) | **Do not share.** Lists the interface / service / rule names Zee disabled |
| Restore token (`~/.zee/restore_token`) | (0600) | **Do not share.** It's a secret |
| **Asset profile (`assets.toml`)** | operator's working dir | **Do not share as-is.** Decoy paths (filesystem locations), interface names, and `cut_method` are operator-internal. If you must share a sample, redact `decoy_paths` and `id` to neutral names first |
| **`ZEE_WEBHOOK_URL` (env var)** | shell profile / launcher | **Do not share.** It is your webhook endpoint and often carries a bearer-style query string |
| **`ZEE_CANARY_BASE_URL` (env var)** | shell profile / launcher | **Do not share.** It identifies the operator's external receiver and the URL shape an attacker would dereference |
| Reference implementation source code | `src/zee/`, `tests/`, `docs/` | **Share freely** — MIT-licensed and the whole point of the project |
| Maintenance write-ups | GitHub Discussions, Wiki | **Share freely, please** — OS version, locale, redacted error message, redacted diff, "what fixed it" |
| Industry deployment notes | GitHub Discussions / Wiki | **Share freely** — anonymised business type, decoy directory shape (e.g. `~/Documents/zee-decoys/<files>`), webhook receiver choice (Canarytokens.org / self-hosted / Lambda) |

**Before posting to Discussions or pasting into an AI session**, run
your text through the redaction checklist in
[docs/maintenance/README.md](./docs/maintenance/README.md#-before-you-paste-anything-anywhere--read-this).

Zee itself never sends your event log anywhere. Sharing in
Discussions / Wiki is an explicit, manual choice you make, on the
parts of the experience that help the next operator.

## Honesty boundaries (current release)

These are not "known bugs" — the items in the Known-limitations
section in v0.1 / v0.2 were closed in v0.3. The following are
honestly-published boundaries of what Zee is and is not:

- **Read detection on macOS / Windows requires the operator to set
  `ZEE_CANARY_BASE_URL`** to an external receiver they control
  (Canarytokens.org, a self-hosted webhook, an AWS Lambda, etc.).
  Without it, no canary URL is embedded and read-only touches against
  a macOS / Windows decoy are not observed (safe by default; Linux
  needs no canary because `inotify` reports reads directly).
- **`restore_token` does not stop a root-equivalent attacker.** The
  token file at `~/.zee/restore_token` is 0600 on POSIX hosts (Linux,
  macOS); a same-user attacker with shell access can still read it.
  The token blocks accidental restores from another shell session
  and casual non-root attackers. For multi-user production
  deployments, wrap `zee restore` in `sudo` or run Zee under a
  dedicated user — `restore_token` is a complement, not a
  replacement, for OS-level access control.
- **On Windows the POSIX permission check is skipped.** NTFS uses
  ACLs rather than POSIX bits and `os.stat().st_mode` reports `0666`
  regardless of the real ACL. Zee therefore does not enforce the
  group/world-read refusal on win32; the effective protection on
  Windows is the per-user NTFS ACL that the OS applies to
  `%USERPROFILE%\.zee` by default. Operators running on shared
  Windows profiles should review that ACL.
- **Windows hardware is not yet hands-on tested by the maintainer.**
  The Windows watcher and cut/restore paths are implemented and
  exercised on every push by the GitHub Actions matrix
  ([test.yml](.github/workflows/test.yml)) on
  `windows-latest` with Python 3.11 / 3.12 / 3.13, including pytest,
  CLI smoke (`zee --version`, `zee capability`,
  `zee init-restore-token`), and PowerShell / netsh enumeration
  parsers. Continuous-run verification on Japanese / German / French
  Windows hosts is still pending — the CI runner is en-US.
