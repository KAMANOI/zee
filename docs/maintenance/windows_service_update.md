# Maintenance prompt — Windows `netsh` / `Get-NetAdapter` / locale / Service change

## When to use this

Use this template when:

- `netsh interface show interface` output changes (column names, row
  format, or locale display).
- `Get-NetAdapter` PowerShell cmdlet changes its output schema (the
  JSON keys `Name` and `Status`).
- Your Windows host is non-English (Japanese, German, French, …) and
  one of the enumeration paths fails.
- A future privsep build of Zee needs to register as a Windows
  Service and the Service Control Manager (SCM) semantics changed.
- `ReadDirectoryChangesW` flag values or `FILE_NOTIFY_*` constants
  change.

## Why this happens

Windows ships locale-translated CLI output in many tools; `netsh` is
notorious for this. The PowerShell-first path (`Get-NetAdapter`) in
v0.3+ is locale-independent, but if Microsoft renames the cmdlet or
changes the JSON keys, Zee's parser breaks.

## Files likely to need editing

- `src/zee/responder/cut_full.py` (`list_windows_interfaces`,
  `_list_windows_interfaces_via_powershell`,
  `_list_windows_interfaces_via_netsh`, `_cut_full_windows`)
- `src/zee/responder/cut_egress.py` (`_cut_egress_windows`,
  netsh advfirewall scripts)
- `src/zee/recovery/restore.py` (`_restore_targeted_windows`,
  `_restore_windows_compat`)
- `src/zee/watcher/backend_windows.py` (ReadDirectoryChangesW
  constants, ctypes glue)

## Tests that must still pass

- `pytest tests/ -q` in full (especially
  `tests/test_windows_iface_enumeration.py`)
- `zee --version`
- `zee capability`
- `zee init-restore-token`
- `python examples/demo_dry_run.py` (events.jsonl carries `decoy_ref`,
  no `decoy_path` — OS-independent v0.3 invariant)

## ⚠️ Before you paste

- Redact real adapter / interface names, decoy paths,
  `ZEE_CANARY_BASE_URL`, `ZEE_WEBHOOK_URL`, hostnames, customer
  identifiers before sending source files to an AI tool.
- Do **not** paste `events.jsonl`, `metrics.jsonl`,
  `cut_state.jsonl`, `canary_tokens.jsonl`, or
  `%USERPROFILE%\.zee\restore_token`. See
  [SECURITY.md → Shared vs. private logs](../../SECURITY.md#shared-vs-private-logs-v05).
- On a work-issued Windows host, confirm your employer's policy
  permits sending source code to a third-party AI service.

## Paste this into Claude / Cursor / Copilot / Codex

```text
You are helping me patch the Zee project (an open-source post-intrusion
decoy tripwire, https://github.com/KAMANOI/zee) after a Windows update
or because my locale is not English.

# Repository context
- Python standard library only; no third-party runtime dependency.
- 3 OS support: Linux (inotify), macOS (kqueue), Windows
  (ReadDirectoryChangesW + Get-NetAdapter + netsh fallback).
- Maintained as a "seeded OSS": each user is expected to keep their
  fork working on their own Windows revision / locale.
- The full pytest suite must remain green on Linux / macOS / Windows.
  The Windows code paths use `monkeypatch` stubs in tests so they
  run on any host.

# What I'm seeing on my Windows box

Windows version (`winver` or PowerShell
`[Environment]::OSVersion`):
[PASTE OUTPUT]

System locale (`Get-WinSystemLocale` in PowerShell):
[PASTE OUTPUT, e.g. ja-JP]

Failing command and output:
[PASTE the command (e.g. `zee restore my-asset --token ...`)
 and the error / traceback]

If the issue is with `Get-NetAdapter` JSON, paste the raw output:
[PASTE `Get-NetAdapter | Select-Object Name,Status | ConvertTo-Json -Compress`]

If the issue is with `netsh`, paste the raw output:
[PASTE `netsh interface show interface`]

# Files in scope

Here is the current state of the files most likely to need an edit:

  - src/zee/responder/cut_full.py
  - src/zee/responder/cut_egress.py
  - src/zee/recovery/restore.py
  - src/zee/watcher/backend_windows.py
  - tests/test_windows_iface_enumeration.py

# What I want you to do

1. Identify whether the failure is from a Microsoft-shipped change
   to `Get-NetAdapter` / `netsh` / `ReadDirectoryChangesW`, or from
   the system locale not being en-US.
2. Propose a minimal patch as a unified diff.
3. Preserve the existing public function signatures
   (`list_windows_interfaces(only_enabled=...)`,
   `cut_full(*, asset_id=None, cut_state=None)`, `WindowsWatcher`).
   Internal helpers can be renamed.
4. Add a new test that would have caught this regression. Use
   `monkeypatch` to stub `subprocess.check_output` so the test runs
   on Linux / macOS hosts too.
5. Note any new "Honesty boundary" that should be added to
   `SECURITY.md` (for example "locale X requires a netsh-side
   workaround").

After I apply your patch and `pytest tests/ -q` returns green, I'll
post the diff to https://github.com/KAMANOI/zee/discussions/categories/maintenance-q-a
so others on the same Windows version / locale can copy it.
```

## After it works

Open a Discussion at
<https://github.com/KAMANOI/zee/discussions/categories/maintenance-q-a>
with:

1. Windows version (`winver`)
2. System locale (`Get-WinSystemLocale`)
3. The symptom
4. The diff (or a link to your fork)
5. Whether the maintainer should pull the fix upstream (optional)

That is the "みんなで防災" part of Zee.
