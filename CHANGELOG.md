# Changelog

All notable changes to Zee are documented here. This project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) — but as an
Early Public / Research Project, expect breaking changes between 0.x
releases.

## [0.1.0] — 2026-05-30

First public release.

### Added
- **MVP implementation** (`src/zee/`): decoy tripwire with automated
  containment. Standard library + PyYAML only.
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
- **Policy**: asset profile YAML (`assets.yaml`) with
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
