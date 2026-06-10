# Zee Starter Guide

> 🌐 日本語: [STARTER_GUIDE.md](./STARTER_GUIDE.md)

```
This guide is a starting point.
Completing this guide does not mean your organization is secure.
It only means you have begun preparing.
```

This is a floor, not a ceiling.

---

## About this guide

The Zee Starter Guide is for **any organization or individual** that feels uneasy about defensive preparedness in the age of advanced AI, and wants to **take the first step**.

This guide is not about choosing tools or comparing specific products. It focuses on **understanding where you stand and what to think about**. Before any implementation or operation, the first step in Zee's view is to put into words what you actually want to protect.

This guide is not aimed at a specific industry or organization size. It is for everyone who feels uneasy about attacks in the AI era.

---

## Six starting points

### 1. Write down what worries you

In one page, in plain language (no jargon), write down what worries you.
Customer-data leaks, tampering of past records, business interruption, reputational damage, liability, regulatory violations — the specifics differ across organizations.

If you choose countermeasures before the worry itself is clear, you cannot later judge whether the countermeasures worked.

### 2. List the information you absolutely cannot afford to have stolen

A full inventory is not required. List **3 to 10** items where, if leaked, the core of the business would collapse.

- Customer personal information, transaction history
- Blueprints, source code, formulas, recipes
- Credentials, API keys, internal access privileges
- Strategic plans, undisclosed strategy, M&A-related material

This list is the basis for later deciding what Zee's traps should protect.

### 3. Know the current state of your perimeter defense

List, in bullet points, the perimeter defenses you currently have (firewalls, EDR, patch operations, MFA, etc.). "Believed to be deployed" and "actually working" are not the same.

Just writing down last update, active status, and coverage scope reveals which layers are missing.

### 4. Confirm that detection exists

In one line, write down: **"If we are breached, who notices, and when?"**

If you cannot write it, that is the current state. Zee is not a tool to prevent intrusion; it is a layer that activates **after** intrusion and adds **one narrow, high-confidence detection signal (decoy contact)**. Zee does not replace your **overall** detection posture, but it adds one specific, high-confidence signal to your organization's detection capability. If there is zero operation to receive any such signal, Zee's role does not yet hold. Moving from zero detection to even a little is the first meaningful step.

### 5. Write down recovery handling

In three lines, write down what would happen on the day a breach is confirmed.

- Who takes the initial response?
- Who is contacted?
- What gets stopped, what gets preserved?

If you cannot write this, that is the largest risk. Before technical countermeasures, fixing the people-and-communication order pays off.

### 6. Understand where Zee fits

Finally, confirm where Zee sits among the five steps above.

- Zee does not touch **3, 5** (perimeter defense, the human side of recovery)
- For **4 (detection)**, Zee does not replace your **overall** detection posture. Instead, it adds **one narrow, high-confidence detection signal (decoy contact)**. This is Zee's primary value
- What Zee addresses is **the post-intrusion layer** — make it harder to steal, buy time, emit one narrow high-confidence signal
- Zee does not replace any other layer

---

## What comes next

After finishing this guide, what you have is not "whether to deploy Zee," but **language for where your organization stands and what to do next**.

From there, paths diverge by organization. Zee aims to walk alongside that very first step.

The working MVP (lightweight decoy tripwire with automated containment) lives under `src/zee/`. See [README.en.md](./README.en.md#mvp--a-working-decoy-tripwire) for install steps.

---

## 7. Try dry_run

The MVP runs **dry_run** by default. It does not actually cut connections; it records "when the cut would have happened" into the metrics log. This is the safe window for measuring decoy precision and false-positive rate.

Strongly recommended order for the first run:

1. Copy `examples/assets.example.toml` to `./assets.toml`.
2. Edit `decoy_paths` to point at dummy paths under a Zee-only directory (e.g. `~/Documents/zee-decoys/aws-credentials.decoy`). Keep them OUT of real tool directories like `~/.aws/`.
3. **(macOS / Windows — recommended) Configure a canary receiver.** Linux observes reads directly via inotify and does not need a canary. On macOS / Windows, without `ZEE_CANARY_BASE_URL` set, read-only attacker touches against a decoy are not observed at all. Quickest path using Canarytokens.org:
   1. Open [https://canarytokens.org/](https://canarytokens.org/), choose "DNS / HTTP canary", and generate a token.
   2. Set the generated URL as an environment variable: `export ZEE_CANARY_BASE_URL="https://canarytokens.org/..."`
   3. Start `zee watch` with this variable set. The seeder will embed the canary URL into decoy content; when an attacker dereferences it, Canarytokens.org notifies you (out-of-band — never re-enters Zee's local responder).
4. Leave `response_mode: notify` (no cut, no would-have-cut path).
5. Run your normal workflow for several days to a week. Confirm **zero false positives** — your backup tool, IDE, or indexing daemon should not be tripping the decoys.
6. Once you observe zero false positives, promote individual assets to `response_mode: staged` or `auto`.

**Jumping straight to `auto` is not recommended.** Zee is a layer that loses trust the moment it ensnares your own work. Promoting only after observing zero false positives is the precondition for using Zee long-term.

### Before you promote — `zee init-restore-token`

Once `response_mode: auto` has cut the network, the only way to put it back is `zee restore`. From v0.3, that command requires a **restore token** (so an accidental invocation from a second shell of the same user cannot revert containment).

Run this **once, before** promoting any asset to `auto`, and store the printed token somewhere safe (a password manager, a sealed note, etc.):

```bash
zee init-restore-token
```

To recover, pass the token via `zee restore <asset_id> --token <TOKEN>` or `ZEE_RESTORE_TOKEN=<TOKEN> zee restore <asset_id>`. The token file at `~/.zee/restore_token` is created with mode `0600`. For multi-user production deployments, wrap `zee restore` in `sudo` or run Zee under a dedicated user — a root-equivalent attacker who can read the token file still bypasses this layer.

### Auto-cut trigger conditions (v4 — required reading)

Even after you promote an asset to `response_mode: auto` + `dry_run: false`, **auto-cut fires only on change-class touches** (write / delete / rename / extend). **Read-class touches** (open / read / attribute inspection) **notify only and never auto-cut**.

The reasoning is structural: legitimate bulk readers (backup tools, AV/EDR, file indexers) **read** decoys; they do not **write** to them. With no process attribution from the current watcher backends (Linux inotify / macOS kqueue / Windows ReadDirectoryChangesW), restricting auto-cut to operations that legitimate bulk readers do not perform is the safest possible false-positive control.

If you receive a read-class alert and have no explanation for it, invoke `zee cut <asset_id>` manually to cut (and `zee restore <asset_id>` to recover). Zee does not emit hints that say "ignore safely"; the final call is always yours.

To observe read-only attacker activity on macOS / Windows, set the `ZEE_CANARY_BASE_URL` environment variable to an external endpoint you control (your own webhook receiver, [Canarytokens.org](https://canarytokens.org), an AWS Lambda, etc.) before running `zee watch`. The seeder will then embed canary URLs into the decoy content; when the attacker dereferences one, the operator's external endpoint fires (out-of-band, never re-entering Zee's local responder). If `ZEE_CANARY_BASE_URL` is unset, no canary URL is embedded and read-only touches against a macOS / Windows decoy are not observed (safe by default). Linux observes reads directly via inotify and needs no canary.

---

→ For the Zee overview, see [README.en.md](./README.en.md).
