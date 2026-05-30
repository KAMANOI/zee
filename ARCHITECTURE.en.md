# Zee — Architecture Overview

> 🌐 日本語: [ARCHITECTURE.md](./ARCHITECTURE.md)

```
Project Status:
Early Architecture / Research Preview

This document describes the intended architecture of Zee.

It should not be interpreted as proof that every component is production-ready, independently validated, or suitable for deployment without expert review.
```

---

## Positioning

Zee is intended as a layer that operates **post-intrusion**.
It does not replace perimeter defenses (firewalls, EDR, patching). It is designed to reduce the chance that an intrusion immediately turns into data theft, operational damage, or undetected persistence, in cases where an adversary has already slipped past the perimeter.

The underlying shift is from "build it so it can't break" to **"design it assuming it will be broken."** This is not a thesis Zee invented; it aligns with where current security practice is broadly heading.

---

## Intended end-to-end flow

```
              ┌─────────────────────────────────────────────────┐
              │  Legitimate traffic (intended not to be ensnared) │
              └─────────────────────────────────────────────────┘
                              │
   Intruder ──▶ 1. Behavior observation ──▶ 2. Gatekeepers ──▶ Luring
                                              │ (deterministic gates to reduce false-positive risk)
                                              ▼
                            ┌────────────────────────────────────┐
                            │  Experimental trap environment      │
                            │    (research-stage)                 │
                            │   3. Redirection to decoy data      │
                            │   4. Fake internal network          │
                            └────────────────────────────────────┘
                                              │
                                              ▼
                                  5. Long-term correlation
                                      (low-and-slow APT research)
```

---

## Role of each layer

| Layer | Role | Status |
|---|---|---|
| 1. Behavior observation | Observes selected process, file, and network behaviors to identify suspicious deviations | Mechanism public |
| 2. Gatekeepers | Sit between detection and luring; uses deterministic gates to reduce the risk of false positives | Mechanism public |
| 3. Decoy redirection | In controlled configurations, may redirect or replace selected access attempts toward marked decoy data | Research-stage |
| 4. Fake internal network | Aims to raise the cost and time of reconnaissance with a convincing fake environment | Research-stage |
| 5. Long-term correlation | Research direction for connecting stealthy attacks spanning months | Research-stage |

Each research-stage item has not been independently validated for effectiveness.

---

## Safety principles (minimizing false positives)

The biggest risk of a post-intrusion layer is **mistakenly ensnaring legitimate processes or staff**. Zee aims to **minimize** that risk; it does not promise zero.

- Place **dual gatekeepers** between detection and luring
- Satisfy the conflicting requirements of "minimizing false positives" and "detecting serious attacks" not by cramming them into one mechanism, but by **separating responsibilities**
- Decisions are made by **deterministic rules**, not at the AI's discretion

Concrete activation conditions and thresholds are parameters refined during implementation, and some are still under research.

---

## Privacy principles

- Raw IP addresses and personally identifiable information are never stored in plaintext in any log field (redacted/hashed just before storage)
- Accumulated data is automatically deleted once it expires
- Correlation is keyed on the "session" (acting subject), not the individual, so legitimate users are never part of the analysis

These are design goals. Whether each implementation stage actually honors them should be checked in the implementation-side documentation.

---

## Dependencies and distribution

- Designed to run on the Python standard library only (fewer dependencies = smaller attack surface)
- Everything in this repository is open under the MIT License

---

## Research direction

The research direction around trap diversification is discussed separately:
→ [RESEARCH.en.md](./RESEARCH.en.md)

The affine Collatz research referenced there is described as a **research direction**, not as a cryptographic or containment guarantee.

---

## Implementation status

| Component | Status | Location and notes |
|---|---|---|
| 1. Behavior observation (decoy tripwire) | ✅ Implemented | `src/zee/watcher/` — Linux inotify (open/read/modify), macOS kqueue (change-only) + canary fallback, Windows ReadDirectoryChangesW + canary (Windows hardware untested) |
| 2. Gatekeepers | Partial | `src/zee/policy/` — allowlist data structure done; wiring into the responder (downgrading contain when allowlist matches) and the multi-signal trap gate are next |
| 3. Decoy redirection | Research-stage | Design only |
| 4. Fake internal network | Research-stage | Design only |
| 5. Long-term correlation | Research-stage | See RESEARCH.en.md (CDS / affine Collatz) |
| Response (automated containment) | ✅ Implemented | `src/zee/responder/` — per-OS full / egress cuts, **dry_run by default** |
| Notification | ✅ Implemented | `src/zee/notifier/` — local required, webhook optional |
| Recovery | ✅ Implemented | `src/zee/recovery/` — `zee restore <asset_id>` (manual only) |
| Telemetry | ✅ Implemented | `src/zee/telemetry/` — JSON Lines, latency, false-positive markers |

Installation and commands → [README.en.md MVP section](./README.en.md#mvp--a-working-decoy-tripwire)

---

<sub>Detailed per-layer notes and later phases will follow.</sub>
