# Changelog

All notable changes to Zee are documented here. This project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) — but as an
Early Public / Research Project, expect breaking changes between 0.x
releases.

## [0.5.0] — 2026-06-01

**Zee becomes a collective.** This release does not add any
detection or containment behaviour — it formalises the operating
model the project will use from here onward: a **seeded OSS** where
the maintainer publishes a reference implementation, and the people
who actually use Zee keep their forks alive in their environments.

The motto is **"defense by everyone, for everyone — みんなで防災"**.

### Why this release

Through v0.1–v0.4 the maintainer chased every OS shift personally.
That model does not scale (it's the classic OSS maintainer-burnout
trap) and it does not match Zee's own "this is a floor, not a
ceiling" stance. v0.5 makes the seeded-OSS model explicit so a
single operator's drift never becomes the project's drift.

### Added

- **`CONTRIBUTING.md` rewrite** introducing the "seeded OSS / 各自
  メンテ" model. Explains why PRs are welcome but not required, why
  the maintainer does not promise to chase OS updates forever, and
  what `docs/maintenance/` is for.
- **`docs/maintenance/` directory** with prompt templates for the
  common failure modes:
  - `mac_launchd_update.md` — Apple ships an `launchd` /
    `networksetup` / `pfctl` / `kqueue` change
  - `linux_systemd_update.md` — `nmcli` / `nft` / `iptables` /
    `inotify` shifts or distro switch
  - `windows_service_update.md` — `Get-NetAdapter` / `netsh` /
    locale / Service registration shifts
  - `python_version_bump.md` — new Python release deprecates
    something Zee depends on
  Each template hands the AI tool (Claude / Cursor / Copilot /
  Codex) enough context to produce a working patch as a diff. The
  recommended flow ends with "post your fix to Discussions".
- **GitHub issue / PR templates** (`.github/ISSUE_TEMPLATE/` and
  `.github/PULL_REQUEST_TEMPLATE.md`) that route environment-specific
  problems toward GitHub Discussions instead of the Issue tracker,
  and explicitly position upstream merge as one outcome among
  several (the others being "post your write-up to Discussions",
  "edit the Wiki", "just keep your fork").
- **README ja/en "みんなで防災" section** at the top of the user-
  facing prose.
- **LP (`docs/index.html`) collective block** between Limitations and
  Get-it, with four cards (Maintenance Q&A / Show your fork / Wiki /
  docs/maintenance).
- **`SECURITY.md` "Shared vs. private logs" table** — clarifies
  exactly which Zee artefacts are safe to share in Discussions /
  Wiki and which are private to the operator. `events.jsonl`,
  `canary_tokens.jsonl`, `cut_state.jsonl`, `restore_token` stay
  private. Source code and maintenance write-ups are shared freely.
- **CLI hint on ZeeError** — when `zee` exits with an error the
  next line nudges the operator toward
  https://github.com/KAMANOI/zee/discussions/categories/q-a
  so they can search for / share their fix.

### Operator action needed (once)

The maintainer needs to enable GitHub Discussions and the Wiki on
the repository for the URLs above to resolve. Until that switch is
flipped, the links resolve to a "this is disabled" page; no code
breakage, just a flat experience for arriving readers. This is a
two-click toggle in the repo Settings.

### Changed

- **CLI stderr on `ZeeError`** — `zee` now appends a two-line hint
  pointing at `Discussions / Maintenance Q&A` after most error
  prints. The exit code and the primary error message are unchanged,
  but `stderr` carries the extra hint. Plain user-input errors
  (`Z102` unknown asset, `Z602`/`Z603`/`Z604` restore-token problems)
  suppress the hint so the operator is not pointed at a community
  board for a typo.

### Not changed

- No detection / containment / restore behaviour changed. No
  on-disk file layouts (`events.jsonl`, `cut_state.jsonl`,
  `canary_tokens.jsonl`, `restore_token`) changed. v0.4.1 state is
  forward-compatible.
- All 78 unit tests still pass on Linux / macOS / Windows × Python
  3.11 / 3.12 / 3.13 in the CI matrix.

## [0.4.1] — 2026-05-31

The v0.4.0 CI matrix surfaced two Windows-specific issues that were
invisible while only the maintainer's macOS shell ran the suite.
Both fall out of NTFS using ACLs rather than POSIX bits and out of
Windows using ``\\`` as the path separator. None of v0.3's
documented invariants change; the fix is to skip the POSIX-only
behaviour on win32 and update the tests to match.

### Fixed
- ``recovery/auth.load_token``: skips the POSIX group/world-read
  refusal on win32 (NTFS ACLs cover the same threat there; the
  fall-through still reads the token). The check is unchanged on
  Linux / macOS.
- ``policy/allowlist._is_path_secure``: skips the POSIX
  group/world-write refusal on win32 for the same reason; the
  loader still rejects unreadable / missing files on every OS.
- ``test_canary_token`` / ``test_cut_state`` / ``test_restore_auth``
  / ``test_allowlist``: owner-only-mode assertions are guarded by
  ``pytest.mark.skipif(sys.platform == "win32")``. The path-
  normalisation test now uses ``tmp_path`` so it exercises real
  absolute paths on every OS (the previous hard-coded ``/tmp/...``
  fed Windows a string the loader normalised to ``\tmp\...``).

### Documentation
- ``SECURITY.md`` "Honesty boundaries" entry on the restore_token
  now states that on Windows the POSIX bit check is skipped and the
  effective protection is the per-user NTFS ACL on ``%USERPROFILE%
  \\.zee``.

## [0.4.0] — 2026-05-31

The 78-test suite from v0.3 now runs on every push across the full
support matrix. The v0.3 "Windows hardware is not yet tested by the
maintainer" entry in `SECURITY.md` is replaced with the CI link.

### Added
- **GitHub Actions test matrix**
  (`.github/workflows/test.yml`): Ubuntu / macOS / Windows ×
  Python 3.11 / 3.12 / 3.13 = 9 jobs, plus a dedicated
  `canary-configured` job that runs the suite under
  `ZEE_CANARY_BASE_URL`. Each job runs `pytest`, then smoke-tests
  the CLI (`zee --version`, `zee capability`,
  `zee init-restore-token`). Action versions are pinned by SHA.
- **Dependabot** (`.github/dependabot.yml`): weekly bumps for the
  pinned GitHub Actions SHAs.
- **README CI badge** (ja / en): live build status link to the
  Actions runs.
- **`examples/seed_demo_decoys.py`**: one-shot script that drops
  three example decoys under `~/Documents/zee-decoys/`, prints the
  paste-able `[[assets]]` stanza, and optionally takes
  `--canary-base-url` to exercise the v0.2 canary path locally.
- **`examples/Dockerfile.linux-smoke`**: minimal Python 3.13 image
  that runs `pytest` and the CLI smoke under a non-root user. Stands
  in for a maintainer Linux machine when verifying a release.
- **`tests/__init__.py`**: empty file so IDE indexers and `pytest`
  plug-ins that walk `__init__.py` chains discover the test package
  without surprises.
- **pyproject.toml `[project.urls]`**: Issues / Changelog /
  Documentation / Sponsor / Security Advisories entries.

### Changed
- `SECURITY.md`'s "Honesty boundaries" entry on Windows hardware now
  points to the CI matrix instead of saying "untested".

### Tests
- 78 unit tests passing (same suite as v0.3.0), now exercised across
  the full OS / Python matrix on every push.

## [0.3.0] — 2026-05-31

Closes every "Known limitation" listed in v0.2's `SECURITY.md`. The
"Known limitations (current release)" section is now empty and has
been removed.

### Added
- **`zee init-restore-token`** (spec L3). Generates a 256-bit
  restore_token at `~/.zee/restore_token` (0600, parent 0700) and
  prints it once. `zee restore` now requires `--token <TOKEN>` or
  `ZEE_RESTORE_TOKEN=<TOKEN>`. Standard library only; constant-time
  comparison via `hmac.compare_digest`. A `restore_token` file with
  loose permissions (group/world read or write) is refused at load
  time. Stops a casual same-user attacker from reverting containment
  from a second shell session; root-equivalent attackers still
  bypass it (the README recommends wrapping `zee restore` in `sudo`
  or running Zee under a dedicated user for multi-user deployments).
- **Cut-state log** (`src/zee/telemetry/cut_state.py`, spec L2).
  Each cut writes a `cut` record to
  `~/.local/state/zee/cut_state.jsonl` (0600 / parent 0700) listing
  the specific interfaces, services, or firewall-rule names Zee
  modified. `zee restore` reads the latest unresolved record and
  reverses only those changes; the v0.2 "enable everything" side
  effect (re-enabling interfaces that another tool had disabled at
  the same time) is gone. Missing or absent records fall back to
  the v0.2 behaviour with a stderr warning.
- **PowerShell `Get-NetAdapter`** for Windows interface enumeration
  (spec L1). Locale-independent — works on Japanese / German /
  French / etc. Windows where the legacy `netsh interface show
  interface` parser returned zero results. The netsh parser is
  retained as a fallback for environments where PowerShell is
  unavailable.
- **Error codes**: `Z602` (restore token required), `Z603` (restore
  token not initialised), `Z604` (restore token invalid).
- New tests: `test_cut_state.py` (7 cases), `test_restore_auth.py`
  (9 cases), `test_windows_iface_enumeration.py` (4 cases). Total
  test suite: 78 (was 56 on v0.2.0).

### Changed
- **`events.jsonl` schema** (spec L4): `decoy_path` is no longer
  persisted. Each `trap_event` record carries `decoy_ref` of the
  form `"<asset_id>#<index>"` (0-based index into the asset's
  `decoy_paths`). A root attacker reading the log alone can no
  longer enumerate every decoy's filesystem location; correlation
  back to the full path goes via `assets.toml`. This is a
  log-format breaking change for downstream analysis tools.
- **`cut_full()` / `cut_egress()` signatures** gain optional
  `asset_id=` and `cut_state=` keyword args. The `tuple[bool, str]`
  return type is unchanged. Internal stubs and the responder pass
  both so the cut-state record is written.
- **`restore()`** reads the cut-state log and undoes only the
  specific changes Zee recorded.

### Tests
- 78 unit tests passing (`pytest tests/`).

### Migration notes
- Existing `events.jsonl` files written by v0.1 / v0.2 still contain
  `decoy_path`. New entries from v0.3 onwards use `decoy_ref`.
  Downstream parsers must accept both keys for the transition window.
- Operators upgrading from v0.2 must run `zee init-restore-token`
  once before they can call `zee restore` again. The token file
  lives at `~/.zee/restore_token`.

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
