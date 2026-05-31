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

## End-to-end flow (actual MVP path)

The diagram below traces what the MVP **actually does**. The
"Gatekeepers (allowlist)" box is shown as a **future insertion point**
that is **NOT wired** in the current build — the watchers cannot
report the touching process, so the allowlist has no input to match
on. Luring / decoy redirection / fake internal network / long-term
correlation remain research-stage and are not in this release.

```
              ┌──────────────────────────────────────────┐
              │  Legitimate traffic (intended not ensnared) │
              └──────────────────────────────────────────┘
                              │
Intruder ──▶ 1. Behavior observation (per-OS watcher)
                              │  TrapEvent carries op_class={read|change}
                              │  as a structured field.
                              ▼
                  ┌──────────────────────────────────────┐
                  │  2. Gatekeepers (allowlist)           │
                  │     NOT wired in current build        │
                  │     (no process attribution from      │
                  │      watchers; future insertion point) │
                  └──────────────────────────────────────┘
                              │
                              ▼
              ┌──────────────────────────────────────────┐
              │ 6. Local notification (required, hinted) │
              │    read  → "could be a legitimate bulk    │
              │             reader; verify"               │
              │    change → "legitimate software does not │
              │              normally do this"            │
              ├──────────────────────────────────────────┤
              │ 7. Webhook (async, best-effort)           │
              ├──────────────────────────────────────────┤
              │ 8. Mode resolve (contain / staged / notify) │
              ├──────────────────────────────────────────┤
              │ 9. Auto-cut gate (ALL of):                │
              │      mode == "contain"                    │
              │    ∧ confidence == "high"                 │
              │    ∧ op_class == "change"   ← v4 added    │
              │    ∧ not dry_run                          │
              │    ↓ all satisfied                         │
              │      cut (per-OS full / egress)           │
              │    ↓ any missing                          │
              │      no cut, notification only            │
              ├──────────────────────────────────────────┤
              │ 10. Latency recorded (events / metrics jsonl) │
              └──────────────────────────────────────────┘

  read touches : blocked at gate 9 by op_class condition; operator
                 reviews the hinted notification and invokes
                 `zee cut <asset_id>` manually if hostile.
  change touches: auto-cut when all four gate conditions are met.
```

Concrete implementation status is detailed in the "Implementation
status" table at the end of this document.

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

The current MVP **does not collect or store attacker IPs**. None of the
watcher, responder, or telemetry paths touch IP addresses or personally
identifiable information. What gets recorded is: which decoy was
touched, when, what kind of touch — and the cut latency if automated
containment ran. That is all.

**Canary tokens — boundary note.** Zee does not run an HTTP listener
for its read-detection canary URLs. The URL fires at an **operator-
provided external endpoint** (your own webhook receiver,
Canarytokens.org, an AWS Lambda, etc.). When the attacker dereferences
the URL, the source IP **may be captured at that external endpoint** —
but that capture happens outside Zee, and it is governed by the
privacy policy of whoever runs that endpoint. The token_id itself is
generated with `secrets.token_urlsafe` and carries no operator
identifier inside Zee.

`policy/allowlist.py`'s `ip_cidrs` / `is_protected(ip=...)` are **not
called by any current watcher backend**. They are a placeholder for a
future relay/correlation phase. There is no path in this release that
makes Zee collect or store attacker IPs.

If an IP-collection path is added in the future, plaintext storage is
not on the table. A bare hash is also not acceptable, because for IPv4
the keyspace is small enough to brute-force back to the original
address. Because Zee's threat model assumes the attacker is on the
host, a keyed HMAC whose key is stored on the host is also vulnerable
(the attacker can read the key). The default choice for that future
phase will be **last-octet truncation** (IPv4 /24, IPv6 /48). If HMAC
is chosen instead, the key must live off-host.

Other principles:
- Accumulated data is automatically deleted once it expires (design goal)
- If correlation is added, it is keyed on the "session" (acting subject), not the individual

These are design goals. Whether each implementation stage actually honors them should be checked in the implementation-side documentation.

---

## Dependencies and distribution

- Current release runs on the Python standard library only — zero third-party runtime dependencies (TOML parsing uses `tomllib`)
- Everything in this repository is open under the MIT License

---

## Defending Zee itself

`cut_full` / `cut_egress` in the responder, and `zee restore` in
recovery, require OS-level network and recovery privileges. That makes
Zee itself a high-value target for a post-intrusion adversary: if an
attacker can rewrite Zee's config, the cut backends, or the logs, they
can make Zee miss real attacks or roll back containment.

### Implemented in this release

- **Config file protection** — `policy/allowlist.py` checks the
  allowlist JSON file and its parent directory for group / world
  write permissions at startup and refuses to load if they are loose.
  This already blocks the simplest allowlist-tamper path.
- **Decoy self-disappearance detection** — the Linux backend
  subscribes to `IN_DELETE_SELF / IN_MOVE_SELF` so a decoy being
  deleted or renamed surfaces as a high-confidence event.
- **Owner-only logs (v4 optional 2, implemented)** —
  `telemetry/events_log.py` creates the log directory at 0700 and
  `events.jsonl` / `metrics.jsonl` at 0600. `decoy_path` is recorded
  in plaintext, so this prevents a non-root co-tenant on the host
  from enumerating decoys by reading the event log. **A root-equivalent
  attacker still reads everything** — that is the privilege-separation
  problem below.

### Known weak points (also listed in Limitations)

- **`zee restore` has no authentication** — anyone who can run the
  CLI (not necessarily root; any user with a session that can invoke
  it) can revert containment. This is the flip side of the safer
  "no auto-reconnect" design: an attacker who has obtained a shell
  on the host can roll back the cut. The MVP intentionally does not
  add authentication (it assumes a single operator). For multi-user
  deployments, wrap `zee restore` with sudo / file permissions or run
  Zee under a dedicated user.

### Design intent retained for future phases

- **Privilege separation** — split watcher / policy / responder into
  separate processes (or users) under least privilege. The watcher
  should not hold cut privilege; the responder reacts only to decoy
  events.
- **Tamper-evident logs** — protect the event log with an append-only
  filesystem feature (Linux append-only attribute, macOS SIP) or take
  periodic hash chains so post-hoc tampering can be detected.
- **`zee restore` authentication** — for multi-user use, add an
  authentication layer (PAM / public key / FIDO2). Out of scope for
  the MVP.

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
