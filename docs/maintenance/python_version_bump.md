# Maintenance prompt — Python version bump / stdlib API change

## When to use this

Use this template when:

- A new Python release deprecates or removes an API Zee relies on
  (`tomllib`, `select.kqueue` flags, `ctypes` quirks, `secrets`
  surface, `subprocess` defaults …).
- You want to run Zee on a Python the maintainer never tested.
- `pip install -e ".[test]"` fails on a future Python.

## Why this happens

Python 3.x continues to deprecate and remove APIs each release. The
CI matrix currently covers 3.11 / 3.12 / 3.13. Future Pythons may
require small changes.

## Files likely to need editing

- `pyproject.toml` (`requires-python`)
- `src/zee/config/schema.py` (uses `tomllib`)
- `src/zee/watcher/backend_*` (ctypes / select API surface)
- Any file that calls newly-removed stdlib APIs

## Tests that must still pass

- `pytest tests/ -q` on the new Python
- `pytest tests/ -q` on the existing supported Pythons too — do not
  drop a supported version casually

## ⚠️ Before you paste

- The Python-version templates rarely need operator-internal data,
  but if you do paste your own `assets.toml` or backtrace, redact
  decoy paths, hostnames, `ZEE_CANARY_BASE_URL`, `ZEE_WEBHOOK_URL`.
- Do **not** paste `events.jsonl`, `metrics.jsonl`,
  `cut_state.jsonl`, `canary_tokens.jsonl`, or `restore_token`. See
  [SECURITY.md → Shared vs. private logs](../../SECURITY.md#shared-vs-private-logs-v05).

## Paste this into Claude / Cursor / Copilot / Codex

```text
You are helping me patch the Zee project (an open-source post-intrusion
decoy tripwire, https://github.com/KAMANOI/zee) so it works on a new
or different Python release.

# Repository context
- Python standard library only; no third-party runtime dependency.
- Currently supports CPython 3.11 / 3.12 / 3.13 in CI.
- Uses `tomllib` (3.11+), `select.kqueue` (macOS), `ctypes` for
  inotify (Linux) and ReadDirectoryChangesW (Windows).

# Python version I want to support

[PASTE `python --version` output]

# What's failing

[PASTE the install error, the import error, or the test failure]

# What I want you to do

1. Identify which Python change caused the failure.
2. Propose a minimal patch as a unified diff that keeps the existing
   supported Pythons (3.11 / 3.12 / 3.13) green and adds the new
   version.
3. If a removed-on-newer API is required, gate the legacy fallback
   behind a `sys.version_info` check — do not split the codebase by
   Python version with separate files.
4. Update `pyproject.toml`'s `requires-python` and the CI matrix in
   `.github/workflows/test.yml` to include the new version.
5. Run `pytest tests/ -q` on at least one of the supported
   versions to confirm regressions are caught.

After I apply your patch and the suite is green, I'll post the diff
to https://github.com/KAMANOI/zee/discussions/categories/maintenance-q-a.
```

## After it works

Open a Discussion at
<https://github.com/KAMANOI/zee/discussions/categories/maintenance-q-a>
with:

1. Python version
2. The diff
3. Whether the maintainer should bump the CI matrix upstream

That is the "みんなで防災" part of Zee.
