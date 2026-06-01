---
name: 🐞 Bug report (reference implementation)
about: Something looks wrong in the reference implementation on main
title: '[bug] '
labels: bug
---

> 📣 **Before you file:** if Zee stopped working in *your environment*
> (after an OS update, in a non-en-US locale, on an untested Python,
> on a distro the reference impl doesn't cover), please open a
> **Discussion** in [Maintenance Q&A](https://github.com/KAMANOI/zee/discussions/categories/q-a)
> instead. The maintainer does not promise to chase OS-shift fallout
> upstream (see [CONTRIBUTING.md](../../CONTRIBUTING.md) — Zee is a
> seeded OSS). Discussions stay searchable and the next person hits
> the same fix in seconds.
>
> ⚠️ **Before pasting source / logs anywhere** (Issue, Discussion, AI
> session): the guide is
> [SECURITY.md → Shared vs. private logs](../../SECURITY.md#shared-vs-private-logs-v05).
> Keep `events.jsonl`, `cut_state.jsonl`, `canary_tokens.jsonl`,
> `restore_token`, `ZEE_WEBHOOK_URL`, `ZEE_CANARY_BASE_URL`, and raw
> `assets.toml` out of public posts.
>
> Use this Issue form only for a bug in the reference implementation
> itself, reproducible on a recent macOS / Ubuntu / Windows.

## Environment

- Zee version (`zee --version`):
- OS:
- Python version:
- Install method (`pip install -e .` / fork SHA / packaged):

## Symptom

What did you do? What did you expect to happen? What happened
instead? Paste the error / traceback in full.

## Minimal reproduction

The smallest set of commands or files that reproduces this on a
fresh checkout.

## Have you searched Discussions?

- [ ] I searched [Maintenance Q&A](https://github.com/KAMANOI/zee/discussions/categories/q-a)
      and this is **not** an environment-specific issue someone else
      has already worked around.
