# Zee — Architecture Overview

> 日本語: [ARCHITECTURE.md](./ARCHITECTURE.md)

> This document is a **high-level design overview**. It does not contain the specific trap activation conditions, thresholds, or anything that directly enables evasion (those are disclosed only to verified applicants).

## Positioning

Zee is a **post-intrusion defense** layer.
It does not replace perimeter defenses (firewalls, EDR, patching); it activates against an adversary who has already slipped past them and is inside.

The design philosophy shifts from "build it so it can't break" to **"design it assuming it will be broken."**
Rather than preventing intrusion itself, Zee makes sure **an intrusion never turns into a result.**

## End-to-end flow

```
              ┌─────────────────────────────────────────────┐
              │  Legitimate business traffic (never ensnared) │
              └─────────────────────────────────────────────┘
                              │
   Intruder ──▶ 1. Behavior detection ──▶ 2. Gatekeepers ──▶ Luring
                                            │ (deterministically prevents false positives)
                                            ▼
                          ┌─────────────────────────────┐
                          │  Trap environment            │
                          │   3. Data poisoning          │
                          │   4. Fake internal network   │
                          └─────────────────────────────┘
                                            │
                                            ▼
                                 5. Long-term correlation (low-and-slow APT)
```

## Role of each layer

| Layer | Role | Disclosure |
|---|---|---|
| 1. Behavior detection | Learns the normal behavior of every process and detects deviation — a general-purpose anomaly detector | Mechanism public |
| 2. Gatekeepers | Stand between detection and luring, deterministically deciding so that legitimate processes and staff are not ensnared | Mechanism public / conditions restricted |
| 3. Data poisoning | Swaps stolen data for marked decoys that reveal the source the moment they are used | Mechanism public / generation & marking rules restricted |
| 4. Fake internal network | A convincing fake environment that raises the cost and time of reconnaissance | Mechanism public / configuration rules restricted |
| 5. Long-term correlation | Connects stealthy attacks spanning months | Mechanism public / detection thresholds restricted |

## Safety principles (preventing false positives)

The biggest risk of post-intrusion defense is **mistakenly ensnaring legitimate processes or staff.** Zee is designed around the following principles.

- Place **dual gatekeepers** between detection and luring.
- Satisfy the conflicting requirements of "zero false positives" and "detecting serious attacks" not by cramming them into one mechanism, but by **separating responsibilities.**
- Decisions are made by **deterministic rules**, not at the AI's discretion (the specific activation conditions are disclosed only to verified applicants).

## Privacy principles

- Raw IP addresses and personally identifiable information are never stored in plaintext in any log field (redacted/hashed just before storage).
- Accumulated data is automatically deleted once it expires.
- Correlation is keyed on the "session" (acting subject), not the individual, so legitimate users are never part of the analysis.

## Dependencies and distribution

- Runs on the Python standard library only (fewer dependencies = smaller attack surface).
- Public: the overall mechanism, this document, and the paper.
- Applicant-restricted: the specific trap activation rules, conditions, and thresholds (identity verified via corporate registration number, etc.; national ID / My Number is never collected).

## Mathematical basis

The undecidability at the core of the trap is based on prime survival in affine Collatz dynamics.
**Prime survival in affine Collatz dynamics (v20)**
→ https://github.com/KAMANOI/collatz-prime-survival/blob/main/paper/prime_survival_affine_collatz_v20.pdf

---

<sub>Additional per-layer explanations are in progress.</sub>
