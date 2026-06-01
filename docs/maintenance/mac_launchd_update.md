# Maintenance prompt — macOS `launchd` / `networksetup` / `pfctl` change

## When to use this

Use this template when a macOS update changes:

- `launchd` / `launchctl` semantics (so the daemon registration in
  any future privsep build no longer works)
- `networksetup -listallnetworkservices` / `-setnetworkserviceenabled`
  output or behaviour (used by `cut_full` on macOS)
- `pfctl` anchor handling (used by `cut_egress` on macOS)
- `kqueue / EVFILT_VNODE` flag values (used by the macOS watcher)

## Why this happens

Apple ships minor changes to `networksetup`, `pfctl`, and `kqueue`
across major macOS releases. The maintainer cannot guarantee the
reference implementation tracks every shift.

## Files likely to need editing

- `src/zee/responder/cut_full.py` (`_cut_full_macos`,
  `list_macos_services`)
- `src/zee/responder/cut_egress.py` (`_cut_egress_macos`)
- `src/zee/recovery/restore.py` (`_restore_targeted_macos`,
  `_restore_macos_compat`)
- `src/zee/watcher/backend_macos.py` (kqueue flag mapping)

## Tests that must still pass

- `pytest tests/ -q` in full (78 + your additions, all green)
- `zee --version`
- `zee capability` (with and without `ZEE_CANARY_BASE_URL`)
- `zee init-restore-token` (token file appears at the path
  `default_token_path()` returns)
- `python examples/demo_dry_run.py` (events.jsonl carries `decoy_ref`,
  no `decoy_path`)

## ⚠️ Before you paste

- Redact real interface / service names, decoy paths,
  `ZEE_CANARY_BASE_URL`, `ZEE_WEBHOOK_URL`, customer identifiers
  before sending source files to an AI tool.
- Do **not** paste `events.jsonl`, `metrics.jsonl`,
  `cut_state.jsonl`, `canary_tokens.jsonl`, or `~/.zee/restore_token`.
  See [SECURITY.md → Shared vs. private logs](../../SECURITY.md#shared-vs-private-logs-v05).
- On a work-issued Mac, confirm your employer's policy permits
  sending source code to a third-party AI service.

## Paste this into Claude / Cursor / Copilot / Codex

```text
You are helping me patch the Zee project (an open-source post-intrusion
decoy tripwire, https://github.com/KAMANOI/zee) after a macOS update
broke one of its OS-specific code paths.

# Repository context
- Python standard library only; no third-party runtime dependency.
- 3 OS support: Linux (inotify), macOS (kqueue / networksetup /
  pfctl), Windows (ReadDirectoryChangesW / netsh / PowerShell
  Get-NetAdapter).
- Maintained as a "seeded OSS": each user is expected to keep their
  fork working on their own OS revision.
- The full pytest suite must remain green on Linux / macOS / Windows.
  The macOS file under inspection here must not break the other OS
  paths.

# What I'm seeing on my Mac

[PASTE YOUR macOS VERSION, e.g. `sw_vers` output]

[PASTE THE FAILING COMMAND AND ITS OUTPUT, e.g.
  $ zee restore my-asset --token ...
  Error: ...
  or the failing pytest line + traceback]

# Files in scope

Here is the current state of the files most likely to need an edit
(paste them in your AI session):

  - src/zee/responder/cut_full.py
  - src/zee/responder/cut_egress.py
  - src/zee/recovery/restore.py
  - src/zee/watcher/backend_macos.py

# What I want you to do

1. Identify which Apple-shipped change in `networksetup`, `pfctl`,
   `launchd`, or `kqueue` causes the failure I'm seeing.
2. Propose a minimal patch as a unified diff.
3. Preserve the existing public function signatures
   (`cut_full(*, asset_id=None, cut_state=None)`,
   `cut_egress(...)`, `list_macos_services()`, `MacOSKqueueWatcher
   .capability()`). Internal helpers can be renamed.
4. Add a new test (or extend an existing one in
   `tests/test_watcher_macos.py` or `tests/test_cut_state.py`) that
   would have caught this regression. Use `monkeypatch` to stub
   `subprocess.check_output` so the test runs on any host.
5. Note any new "Honesty boundary" that should be added to
   `SECURITY.md` if the fix surfaces a new limitation.

After I apply your patch and `pytest tests/ -q` returns green, I'll
post the diff to https://github.com/KAMANOI/zee/discussions/categories/maintenance-q-a
so others hitting this same upgrade can copy it.
```

## After it works

Open a Discussion at
<https://github.com/KAMANOI/zee/discussions/categories/maintenance-q-a>
with:

1. The exact macOS version (`sw_vers -productVersion` output)
2. The symptom
3. The diff (or a link to your fork)
4. Whether the maintainer should pull the fix upstream (optional)

That is the "みんなで防災" part of Zee.
