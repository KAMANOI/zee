# Zee

> 🌐 日本語: [README.md](./README.md)

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
- A broad sweep surfaced **23,000+** vulnerabilities, including a critical flaw in a cryptographic library affecting roughly **5 billion** devices (CVE-2026-5194).

Sources: Anthropic Red Team ([red.anthropic.com](https://red.anthropic.com/)) / Project Glasswing.

These describe **offensive capability**. Zee is not a tool to stop that capability.
What Zee actually addresses is **the gap between the speed at which attack capability evolves and the speed at which defensive preparedness spreads**. Zee aims to narrow that gap a little.

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
cp examples/assets.example.yaml ./assets.yaml
# Edit decoy_paths to point at your own paths

# 2. Start monitoring (default dry_run — no real cut)
zee watch -c ./assets.yaml

# 3. In another window, act as an attacker
cat ~/.aws/credentials.decoy   # Zee records a high-confidence event
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
| macOS | kqueue + canary | no | no | yes | yes | implemented |
| Windows | ReadDirectoryChangesW + canary | no | no | yes | yes | implemented (untested on Windows hardware) |

- **Linux** — `inotify` observes open / read / modify directly (standard library only, via ctypes).
- **macOS** — `kqueue/EVFILT_VNODE` observes change events only. Read detection is not available without the Endpoint Security framework entitlement; instead, Zee embeds canary URLs in decoys and fires out-of-band when those URLs are dereferenced.
- **Windows** — `ReadDirectoryChangesW` observes change events on the parent directory. Read auditing requires Object Access auditing (SACL + Event Log), which is out of scope for v1; canary URLs cover the read path.

Verified on macOS. Linux backend complete in code, continuous-run verification on Linux hardware not yet done. Windows backend implemented, not yet verified on Windows hardware.

---

## Limitations — what Zee does not do

Zee draws its boundary honestly.

- **It does not prevent intrusion itself** — perimeter defenses (firewall, EDR, patching) are not replaced by Zee
- **It is detection-centered** — the automated containment mechanism (MVP) is to be released separately and is not yet documented
- **It has limits** — against machine-speed adversaries, or against very small, very specific secrets (a single API key, etc.), Zee is outside its useful range
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
