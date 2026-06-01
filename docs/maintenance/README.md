# `docs/maintenance/` — when Zee stops working in your environment

This folder is the **first place to look when Zee no longer runs**
after an OS update or in an environment the maintainer never tested.

Zee is run as a **seeded OSS** project (see
[CONTRIBUTING.md](../../CONTRIBUTING.md)). The maintainer publishes a
reference implementation and these maintenance prompts. Keeping your
fork working on your particular OS revision is yours.

## ⚠️ Before you paste anything anywhere — read this

These prompts ask you to paste source files into an AI tool (Claude /
Cursor / Copilot / Codex) and to post your fix to GitHub Discussions
afterward. Both are **outbound channels**: anything you paste leaves
your machine. A short checklist before you do that:

1. **Redact operator-internal identifiers** before pasting into the
   AI session: real interface names, hostnames, decoy paths, your
   `ZEE_CANARY_BASE_URL`, `ZEE_WEBHOOK_URL`, customer / partner
   names that may appear in your `assets.toml`.
2. **Never paste these files**, into AI sessions or into Discussions:
   `events.jsonl`, `metrics.jsonl`, `canary_tokens.jsonl`,
   `cut_state.jsonl`, `~/.zee/restore_token`. They are your private
   operator state. See [SECURITY.md → Shared vs. private logs](../../SECURITY.md#shared-vs-private-logs-v05)
   for the full table.
3. **If you are on a work-issued device**, confirm your employer's
   policy permits sending source code to a third-party AI service
   before you paste. Some industries / contracts forbid it.
4. **When you post your fix to Discussions**, paste the redacted
   patch and a redacted error trace — not the raw machine output.

Sharing the *fix* (the diff, the workaround, the OS version it
applies to) is what "みんなで防災" is about. Sharing *operator state*
is not.

## How to use these prompts

Each `.md` file in this folder is a **prompt template** designed to be
pasted into an AI assistant (Claude, Cursor, Copilot, Codex, …) along
with the error message you are seeing. The template:

1. Frames the situation so the AI understands what Zee is and what
   the failure mode usually is for this class of OS change.
2. Lists the files in the Zee tree that are likely to need an edit.
3. Lists the tests that must still pass after the fix.
4. Asks the AI to produce a patch as a unified diff.

After you apply the patch:

1. Run `pytest tests/` locally to confirm nothing else broke.
2. Run the relevant `zee` smoke commands (`zee --version`,
   `zee capability`, `zee init-restore-token`) to confirm the CLI is
   still intact.
3. **Post your fix to [Discussions → Maintenance Q&A](https://github.com/KAMANOI/zee/discussions/categories/q-a)**
   so the next person to hit this is unblocked fast. Include the OS
   version, the symptom, and the redacted diff (or a link to your
   fork). For *what to share vs. what to keep private*, see
   [SECURITY.md → Shared vs. private logs](../../SECURITY.md#shared-vs-private-logs-v05).

That last step is the "みんなで防災 — defense by everyone, for everyone"
part. Even if your patch never lands upstream, your write-up is what
makes Zee survive as a project.

## Index

| Template | Use it when |
|---|---|
| [mac_launchd_update.md](./mac_launchd_update.md) | A macOS update changed `launchd` / `launchctl` behaviour and Zee's expectations break |
| [linux_systemd_update.md](./linux_systemd_update.md) | A systemd update or a distro switch (nftables semantics, `nmcli` flags, etc.) breaks the Linux paths |
| [windows_service_update.md](./windows_service_update.md) | A Windows update changes `netsh` / `Get-NetAdapter` output, locale handling, or service registration |
| [python_version_bump.md](./python_version_bump.md) | A new Python release deprecates / removes API Zee relies on (`tomllib`, `select.kqueue` flags, `ctypes` quirks) |

## Forking the decoy seeder (read this before you change `src/zee/decoy/seeder.py`)

If your fork edits the decoy templates, **do not put production-shaped
secret strings in plain form** into the template body. GitHub Secret
Scanning will flag the whole repository and your push may be blocked
or, worse, accepted and indexed. The rule (also in
[CONTRIBUTING.md](../../CONTRIBUTING.md)):

- Stripe live key shape: `sk_live_[A-Za-z0-9]{24,}` → include `_` in
  the placeholder body, or split into adjacent literals
  (`"sk" "_live_" "..."`).
- AWS access key shape: `AKIA[0-9A-Z]{16}` → same: include `_`, or
  split (`"AK" "IA..."`).
- The existing `src/zee/decoy/seeder.py` does this already. Keep
  the pattern in your fork.

Otherwise you push a real-looking key shape to your fork, your repo
gets quarantined, and your operator state (issue templates, CI
secrets, …) can end up in a takedown loop.

## Adding a new template

If you hit a class of failure that is not covered by an existing
template, **add one**. The format is:

1. Short headline saying what kind of OS / runtime shift this covers.
2. "Why this happens" — one paragraph on the upstream change.
3. "Files likely to need editing" — paths inside `src/zee/`.
4. "Tests that must still pass" — usually `pytest tests/ -q` in full.
5. The prompt block (in a code fence with `text` language hint) that
   the user pastes into their AI tool.

Then PR it (or just keep it in your fork and link it from
Discussions).
