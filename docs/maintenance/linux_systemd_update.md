# Maintenance prompt — Linux `systemd` / `nmcli` / `nft` / `iptables` change

## When to use this

Use this template when:

- A `systemd` update changes how a future privsep build of Zee would
  register / run.
- `nmcli networking off|on` semantics change (used by `cut_full` on
  Linux).
- `nft` table syntax changes (used by `cut_egress` on Linux).
- `iptables` is replaced by `nftables` on your distro and the legacy
  `iptables` fallback path stops working.
- `inotify` flag values or `IN_*` constants change in a future kernel.

## Why this happens

The Linux user-space toolchain (NetworkManager, nftables, iptables)
moves faster than any single maintainer can chase. Distros also vary:
Debian, Ubuntu, Fedora, Arch each have slightly different ages of
`nft` and `nmcli`. Zee's reference implementation targets a recent-
ish baseline.

## Files likely to need editing

- `src/zee/responder/cut_full.py` (`_cut_full_linux`,
  `list_linux_interfaces`)
- `src/zee/responder/cut_egress.py` (`_cut_egress_linux`, nft / iptables
  scripts)
- `src/zee/recovery/restore.py` (`_restore_targeted_linux`,
  `_restore_linux_compat`)
- `src/zee/watcher/backend_linux.py` (inotify constants, ctypes glue)

## Tests that must still pass

- `pytest tests/ -q` in full
- `zee --version`
- `zee capability`
- `zee init-restore-token`
- `python examples/demo_dry_run.py` (events.jsonl carries `decoy_ref`,
  no `decoy_path` — OS-independent v0.3 invariant)

## ⚠️ Before you paste

- Redact real interface / service names, decoy paths,
  `ZEE_CANARY_BASE_URL`, `ZEE_WEBHOOK_URL`, hostnames, customer
  identifiers before sending source files to an AI tool.
- Do **not** paste `events.jsonl`, `metrics.jsonl`,
  `cut_state.jsonl`, `canary_tokens.jsonl`, or `~/.zee/restore_token`.
  See [SECURITY.md → Shared vs. private logs](../../SECURITY.md#shared-vs-private-logs-v05).
- On a work-issued / production Linux host, confirm your employer's
  or your customer's policy permits sending source code to a
  third-party AI service.

## Paste this into Claude / Cursor / Copilot / Codex

```text
You are helping me patch the Zee project (an open-source post-intrusion
decoy tripwire, https://github.com/KAMANOI/zee) after a Linux update
broke one of its OS-specific code paths.

# Repository context
- Python standard library only; no third-party runtime dependency.
- 3 OS support: Linux (inotify, nmcli, nft, iptables), macOS, Windows.
- Maintained as a "seeded OSS": each user is expected to keep their
  fork working on their own distro.
- The full pytest suite must remain green on Linux / macOS / Windows.
  The Linux file under inspection here must not break the other OS
  paths.

# What I'm seeing on my Linux box

Distribution and version:
[PASTE `cat /etc/os-release | head -3`]

Kernel:
[PASTE `uname -r`]

Tool versions:
[PASTE one or more of: `nmcli --version`, `nft --version`,
 `iptables --version`, `python3 --version`]

Failing command and output:
[PASTE the command and the error / traceback]

# Files in scope

Here is the current state of the files most likely to need an edit
(paste them in your AI session):

  - src/zee/responder/cut_full.py
  - src/zee/responder/cut_egress.py
  - src/zee/recovery/restore.py
  - src/zee/watcher/backend_linux.py

# What I want you to do

1. Identify which upstream change (`nmcli`, `nft`, `iptables`,
   `systemd`, `inotify`) causes the failure I'm seeing.
2. Propose a minimal patch as a unified diff.
3. Preserve the existing public function signatures
   (`cut_full(*, asset_id=None, cut_state=None)`, `cut_egress(...)`,
   `list_linux_interfaces()`, `LinuxInotifyWatcher`). Internal
   helpers can be renamed.
4. Add a new test that would have caught the regression. Use
   `monkeypatch` to stub `subprocess.check_output` and / or
   `ctypes` so the test runs on macOS / Windows hosts too.
5. Note any new "Honesty boundary" that should be added to
   `SECURITY.md` if the fix surfaces a new limitation (for example
   "distro X without nftables now falls back to the compat path").

After I apply your patch and `pytest tests/ -q` returns green, I'll
post the diff to https://github.com/KAMANOI/zee/discussions/categories/q-a
so others hitting this same shift can copy it.
```

## After it works

Open a Discussion at
<https://github.com/KAMANOI/zee/discussions/categories/q-a>
with:

1. Your distro and version (`cat /etc/os-release`)
2. The symptom
3. The diff (or a link to your fork)
4. Tool versions (`nmcli --version`, `nft --version`, etc.)
5. Whether the maintainer should pull the fix upstream (optional)

That is the "みんなで防災" part of Zee.
