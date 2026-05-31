# Zee

> 🌐 日本語: [README.md](./README.md) ｜ 🌐 LP: https://kamanoi.github.io/zee/

> Zee is an open project that helps organizations and individuals move from concern to preparedness in the age of advanced AI.

```
Project Status:
Early Public / Research Project

Zee is not a production-ready security product.

Zee does not currently guarantee protection, containment, prevention of data theft, or detection effectiveness.

This repository currently provides architecture, research direction, preparation guidance, and experimental concepts under active development.
```

---

## Why Zee exists

The starting point is simple: to reduce social anxiety.

AI is a remarkable technology. Adversaries can use it too. The problem is not AI itself; it is that society's preparedness has not kept up.

What we want to protect is everyday safety, trust between people, the honest effort of legitimate businesses, and the value of good intentions. Zee becoming well-known is not the goal. Society staying stable is. If someone builds a better way, that is fine too.

---

## Preparedness in the Mythos era

Attacks now move at machine speed. Finding and weaponizing vulnerabilities has become cheap, fast, and high-volume.

The figures below were all published by Anthropic, the company that builds the AI models.

- A browser vulnerability (Firefox's JavaScript engine) that an older model could turn into working exploit code only twice in several hundred attempts was weaponized **181 times** by a newer model.
- A flaw in OpenBSD that had survived **27 years** of expert audits and automated testing was discovered in **about 1,000 automated attempts for under USD 20,000**.
- A broad sweep surfaced **23,000+ candidate vulnerabilities** (≈1,752 of which were independently validated), including a critical flaw in a cryptographic library affecting roughly **5 billion** devices (CVE-2026-5194).

Sources: Anthropic Red Team ([red.anthropic.com](https://red.anthropic.com/)) / Project Glasswing.

These describe **offensive capability**. Zee is not a tool to stop that capability.
What Zee buys time against is **human-paced or semi-automated post-intrusion activity** — the phase after a breach succeeds, during which an attacker (or attacker AI) performs reconnaissance, lateral movement, and exfiltration. Against a fully autonomous adversary that completes the entire chain in seconds, Zee's useful range is limited (see Limitations).

What Zee addresses is **the gap between the speed at which attack capability evolves and the speed at which defensive preparedness spreads**. Zee aims to narrow that gap a little.

---

## What Zee is

Zee starts not from "do not get breached" but from **"do not get robbed"**. Even more precisely, **"buy time"** — extend the window before specialized response and remediation arrive.

This is a **design goal** at this stage, not a measured or validated performance claim.

**Zee is not:**
- A project to defeat AI
- A national cyber weapon
- A complete defense system
- An affine Collatz advocacy project

**Zee's purpose:** to reduce the number of "zero defense" situations.

---

## What Zee currently offers

At this stage Zee provides:

- **Starter Guide** — the first step in figuring out what to think about ([STARTER_GUIDE.en.md](./STARTER_GUIDE.en.md))
- **Architecture overview** — design intent and the role of each component ([ARCHITECTURE.en.md](./ARCHITECTURE.en.md))
- **Research note** — CDS and affine Collatz research as a research direction ([RESEARCH.en.md](./RESEARCH.en.md))
- **MVP implementation** — a lightweight decoy tripwire with automated containment (`src/zee/` — **dry_run by default**)

---

## MVP — a working decoy tripwire

The MVP lives under `src/zee/`. **It runs dry_run by default and does not actually cut connections.** Automated containment runs only when an asset profile is promoted to `response_mode: auto` AND `dry_run: false`.

### Install

```bash
git clone https://github.com/KAMANOI/zee.git
cd zee
pip install -e .
```

### Run

```bash
# 1. Create an asset profile
cp examples/assets.example.toml ./assets.toml
# Edit decoy_paths to point at your own paths
# The default example uses a Zee-only directory (~/Documents/zee-decoys/)

# 2. (Optional) Wire read detection on macOS / Windows
#    Point ZEE_CANARY_BASE_URL at an external endpoint you control
#    (your own webhook receiver, Canarytokens.org, an AWS Lambda, ...).
#    Without it, Zee still runs, but macOS / Windows decoys do not
#    trip on read-only touches (Linux observes reads directly).
export ZEE_CANARY_BASE_URL="https://your-receiver.example.com/r"

# 3. Start monitoring (default dry_run — no real cut)
zee watch -c ./assets.toml

# 4. In another window, simulate an attacker tampering with the decoy
echo "tampered $(date)" >> ~/Documents/zee-decoys/.env
#  -> change-class touch (modify); Zee records a high-confidence event
#     on all three OSes. On Linux, `cat <decoy>` (read-only) also fires
#     because inotify observes open/read directly. On macOS / Windows,
#     read-only touches fire ONLY when ZEE_CANARY_BASE_URL is set —
#     the canary URL embedded in the decoy is dereferenced and the
#     operator's external endpoint receives the hit (never re-enters
#     Zee's local responder).
```

### What this MVP does / does not do

**Does**:
- Seeds and registers decoy files
- Detects decoy contact (open / read / modify, subject to OS capability) as a high-confidence event
- Sends a local notification and (optionally) a webhook
- For assets with `response_mode: auto`, performs automated containment only when `dry_run: false`
- Measures everything (detection latency, cut completion time, false-positive markers)

**Does not**:
- Prevent intrusion itself (that is perimeter defense; Zee does not replace it)
- Trigger automated containment on heuristic anomalies (decoy contact only)
- Auto-reconnect (recovery is manual: `zee restore <asset_id>`)

### Detection capability matrix

`zee capability` prints this. Current implementation status:

| OS | Backend | open | read | modify | canary fallback | status |
|---|---|---|---|---|---|---|
| Linux | inotify | yes | yes | yes | no | implemented |
| macOS | kqueue [+ canary if `ZEE_CANARY_BASE_URL`] | no | no | yes | yes (when configured) | implemented |
| Windows | ReadDirectoryChangesW [+ canary if `ZEE_CANARY_BASE_URL`] | no | no | yes | yes (when configured) | implemented (untested on Windows hardware) |

- **Linux** — `inotify` observes open / read / modify directly (standard library only, via ctypes). No canary needed.
- **macOS** — `kqueue/EVFILT_VNODE` observes change events only. Read detection is not available without the Endpoint Security framework entitlement, so Zee uses an out-of-band canary URL embedded in the decoy. **Set `ZEE_CANARY_BASE_URL` to enable read detection**: the seeder embeds the URL, and when an attacker dereferences it the operator's external endpoint fires (the hit never re-enters Zee's local responder). Without `ZEE_CANARY_BASE_URL`, no canary URL is embedded and read-only touches against a macOS decoy are not observed.
- **Windows** — `ReadDirectoryChangesW` observes change events on the parent directory. Read auditing requires Object Access auditing (SACL + Event Log), which is out of scope for v1. Same canary mechanism as macOS: **set `ZEE_CANARY_BASE_URL` to enable read detection.**

Where to point `ZEE_CANARY_BASE_URL`:
- **Canarytokens.org** (free, recommended)
- Your own webhook receiver (Cloudflare Worker / AWS Lambda / Vercel Edge Function / ...)
- The downstream Slack / Discord / email routing lives on the operator side of that endpoint

Verified on macOS. Linux backend complete in code, continuous-run verification on Linux hardware not yet done. Windows backend implemented, not yet verified on Windows hardware.

### False-positive control (we are not using a process allowlist — honestly)

The watcher backends in this MVP (Linux inotify, macOS kqueue, Windows ReadDirectoryChangesW) **do not report which process touched the decoy**. As a result, a process-name or exe-path allowlist cannot be consulted at detect time. The allowlist data structure is kept for future use, but is **never invoked from the responder in this release**. Shipping a default allowlist that the responder cannot consult would create a false sense of safety, so no default allowlist is shipped either.

False positives are controlled in two other layers instead.

**1. Placement (the layer that does most of the work)**

Keep decoys outside what your backup tool, AV/EDR, and OS file indexer walk. Concretely:

- **macOS Spotlight exclude**: System Settings → Siri & Spotlight → Privacy → add the decoy folder
- **macOS Time Machine exclude**: System Settings → General → Time Machine → Options → exclude the decoy folder
- **Windows search index exclude**: Settings → Search → Windows Search → Advanced indexing options → remove the decoy path
- **Backup tool exclude**: Backblaze / Arq / Restic etc. — exclude the decoy path
- **AV/EDR exclude**: Microsoft Defender / CrowdStrike / SentinelOne etc. — add the decoy path to the scan exclusion list (within whatever your policy allows)

**2. Trigger limit (the safe-by-construction layer)**

Even for `response_mode: auto` assets, **auto-cut fires only on change-class touches** (write / delete / rename / extend). **Read-class touches** (open / read / attribute inspection) **notify only and never auto-cut.**

Reason: legitimate backup / AV / indexer software reads decoys. It does not normally write to them. So even without identifying the process, the kind of operation is enough to distinguish "what bulk readers do not do" — structurally safer against false positives.

Every notification carries an op-class hint:

- read alert: "could be a legitimate bulk reader. If you have no explanation, verify and run `zee cut <asset_id>` to cut manually."
- change alert: "legitimate software does not normally do this. Treat as suspicious." (auto-cut target if mode=auto and dry_run=false.)

Hints never say "ignore safely". The final call is always the operator's.

For reference: to ever add a process-name allowlist that actually works at detect time, Zee would need a privileged backend (Linux fanotify / macOS Endpoint Security / Windows minifilter). That is incompatible with the MVP's lightweight, low-privilege scope. It will be designed separately if and when needed.

---

## Limitations — what Zee does not do

Zee draws its boundary honestly.

- **It does not prevent intrusion itself** — perimeter defenses (firewall, EDR, patching) are not replaced by Zee
- **It is detection-centered** — automated containment runs only when an asset profile is promoted to `response_mode: auto` AND `dry_run: false`. Default is dry_run (observe only)
- **Auto-cut fires only on change-class touches** — open / read / attribute-inspection touches never auto-cut. The notification carries an operator-facing hint, and the operator decides whether to invoke `zee cut <asset_id>` manually. Reason: with no process attribution from the current watchers, restricting auto-cut to operations that legitimate bulk readers (backup, AV, indexer) do not perform on decoys is the structurally safer rule
- **On macOS / Windows, decoy reads fire only when `ZEE_CANARY_BASE_URL` is set** — kqueue and ReadDirectoryChangesW do not emit read notifications. When `ZEE_CANARY_BASE_URL` is configured, the seeder embeds a canary URL in the decoy and the operator's external endpoint fires on dereference (never re-entering Zee's local responder). When `ZEE_CANARY_BASE_URL` is unset, no canary URL is embedded and read-only touches are not observed. Linux observes reads directly via inotify and does not need a canary
- **The process allowlist does not take effect on the current MVP** — false-positive control relies on placement (keep decoys outside what backup / AV / indexer software walks) and the change-class trigger limit, not on an allowlist match. See the "False-positive control" section above
- **`zee restore` has no authentication** — an attacker who obtains a shell on the host can roll back containment. The MVP intentionally keeps this simple for a single-operator deployment
- **Event log records `decoy_path` in plaintext** — files are owner-only (0700/0600), but a root-equivalent attacker can still read them
- **It has limits** — against fully autonomous machine-speed adversaries, or against very small, very specific secrets (a single API key, etc.), Zee is outside its useful range. Zee buys time against human-paced or semi-automated post-intrusion activity — the phase after a breach succeeds, during which an attacker performs reconnaissance, lateral movement, and exfiltration
- **It is not measured** — effectiveness has not been independently validated. Verify in your own environment before any production use

This is a floor, not a ceiling. We state the failure conditions before claiming safety.

---

## License

[MIT License](./LICENSE). Everything in this repository is open.

---

## Paper

The mathematical background of the design:
**Prime survival in affine Collatz dynamics (v20)**
→ https://github.com/KAMANOI/collatz-prime-survival/blob/main/paper/prime_survival_affine_collatz_v20.pdf

---

## Support

Zee is free. If it helps you, support via GitHub Sponsors is welcome.

---

## Disclaimer

- Zee is currently at the **Early Public / Research Project** stage
- Zee is **not a silver bullet** — it does not prevent intrusions and does not detect every attack
- Machine-speed offensive capability keeps advancing. As newer models become widely available, **Zee itself will need vulnerability review and patching**
- Zee does not replace perimeter defense or patching operations — it is **one additional layer that complements them**
