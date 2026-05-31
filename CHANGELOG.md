# Changelog

All notable changes to Zee are documented here. This project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) — but as an
Early Public / Research Project, expect breaking changes between 0.x
releases.

## [0.2.0] — 2026-05-31

Canary URL wiring: macOS / Windows read detection moves from "planned"
to working. The v0.1 honesty disclosure ("read-only attacker activity
against a macOS / Windows decoy is not observed") is lifted when
operators configure a receiving endpoint.

### Added
- **Canary URL embedding in the seeder.** When the operator sets
  ``ZEE_CANARY_BASE_URL`` to an external receiver they control
  (Canarytokens.org, a self-hosted webhook, an AWS Lambda, …), the
  env / credentials / notes templates now carry a canary URL line of
  the form ``{base_url}/{token_id}``. ssh_key templates are left
  alone (the OpenSSH armor format does not survive a foreign URL).
  Embedded lines contain no Zee-origin words (``canary`` / ``zee`` /
  ``tripwire`` / ``decoy``); the entire rendered decoy is now
  free of those markers (enforced by ``tests/test_seeder_canary.py``).
- **Persistent ``CanaryTokenRegistry``.** Issued tokens append to
  ``~/.local/state/zee/canary_tokens.jsonl`` (parent dir 0700, file
  0600), so restarting ``zee watch`` with the same ``base_url``
  rebinds the same URL to each decoy_path (idempotent across runs).
  Records whose ``base_url`` differs from the current configuration
  are skipped on load.
- ``zee capability`` and the per-OS ``Capability`` reflect whether
  ``ZEE_CANARY_BASE_URL`` is configured (``uses_canary_fallback``).
- Operator-facing receiver guidance in README, ARCHITECTURE,
  STARTER_GUIDE, business_guide, and ``assets.example.toml``.

### Changed
- Decoy template body strings no longer contain ``zee`` or ``decoy``;
  attackers cannot ``grep`` for those words to identify decoys.
- ``CanaryTokenRegistry.issue`` / ``issue_for_decoy`` now raise
  ``RuntimeError`` when ``base_url`` is unset. The ``about:zee/c/…``
  fallback was removed — emitting a clearly Zee-origin URL into a
  decoy made the deception trivially detectable.
- ``CanaryTokenRegistry`` ``base_url`` validation accepts
  case-insensitive ``https://`` and strips whitespace before checking.
- Canary URL shape is ``{base_url}/{token_id}`` (no ``/c/`` prefix);
  the operator's chosen path structure is what an attacker sees.

### Tests
- 56 unit tests passing (``pytest tests/``). Added
  ``test_seeder_canary.py`` (8 cases) and expanded
  ``test_canary_token.py`` (9 cases: persistence, idempotency,
  base_url switching, owner-only file mode).

### Migration notes
- Existing decoy files from v0.1 deployments are not rewritten on
  upgrade (the evidence-preservation rule). To embed canary URLs in
  files that pre-date v0.2, delete the existing decoy file under your
  Zee-managed directory and let ``zee watch`` re-seed it.

## [0.1.0] — 2026-05-30

First public release.

### Added
- **MVP implementation** (`src/zee/`): decoy tripwire with automated
  containment. Standard library only (TOML config via `tomllib`; no
  third-party runtime dependency).
- **Watcher backends**:
  - Linux: `inotify` via ctypes (open / read / modify, plus
    delete-self / move-self for decoy disappearance).
  - macOS: `kqueue/EVFILT_VNODE` (change events) + canary URL fallback
    for read signals.
  - Windows: `ReadDirectoryChangesW` via ctypes (change events) +
    canary URL fallback (untested on Windows hardware).
- **Responder**: fixed notify → fire-and-forget webhook → mode resolve
  → `confidence=high` only contain. `dry_run` is the default.
- **Cut backends** (per-OS): `full` (interface disable) and `egress`
  (block outbound to non-local destinations). Both require admin
  privilege and never run on `dry_run`.
- **Policy**: asset profile TOML (`assets.toml`) with
  `response_mode` × `cut_method` resolution. Allowlist data structure
  for legitimate processes (responder wiring is a follow-up phase).
- **Recovery**: manual `zee restore <asset_id>` — no auto-reconnect.
- **Telemetry**: JSON Lines event log, latency metrics, false-positive
  markers, capability matrix.
- **Documentation**: README / ARCHITECTURE / STARTER_GUIDE / RESEARCH
  in Japanese and English.
- **OSS governance**: LICENSE (MIT), SECURITY.md, CONTRIBUTING.md,
  CODE_OF_CONDUCT.md.

### Design choices that are intentionally not features
- No automatic reconnection after a cut. Recovery is always manual.
- No "defense rate" numbers. Effectiveness is not independently
  validated and we will not publish a percentage that isn't measured.
- No applicant-restricted / gated distribution. Everything is MIT.
- No promise that Zee stops any named attacker class.

### Tests
- 33 unit tests passing (`pytest tests/`). Covers confidence gate,
  dry_run, mode resolution, async webhook non-blocking, duplicate-decoy
  detection, macOS kqueue change events.

### Known limitations
- Linux backend: code complete; continuous-run verification on Linux
  hardware not yet done.
- Windows backend: code complete; not yet verified on Windows hardware.
- macOS: verified on developer hardware.
