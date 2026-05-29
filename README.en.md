# Zee

> 🌐 日本語: [README.md](./README.md)

**Intrusion can no longer be stopped 100%. So Zee defends what happens *after* the breach.**

Zee is a free, open-source **post-intrusion defense layer** that activates *after* an attacker is already inside.
It does not replace perimeter defenses (firewalls, EDR, patching). Instead, against an adversary who has slipped past them, Zee **lets them steal, neutralizes what they take, and exposes them** — so that a breach never pays off.

> ⚠️ This repository is a proof-of-concept (PoC). Validate in your own environment before any production use. See [Disclaimer](#disclaimer).

---

## Why now — attacks at machine speed

Finding and weaponizing vulnerabilities has become cheap, fast, and high-volume. The figures below were all published by Anthropic, the company that builds the AI models.

- A browser vulnerability (Firefox's JavaScript engine) that an older model could turn into working exploit code only twice in several hundred attempts was weaponized **181 times** by a newer model.
- A flaw in OpenBSD that had survived **27 years** of expert audits and automated testing was discovered in **about 1,000 automated attempts for under USD 20,000**.
- A broad sweep surfaced **23,000+** vulnerabilities, including a critical flaw in a cryptographic library affecting roughly **5 billion** devices (CVE-2026-5194).

Sources: Anthropic Red Team ([red.anthropic.com](https://red.anthropic.com/)) / Project Glasswing

> These figures describe **offensive (research-side) capability**. Zee operates on **post-intrusion defense** — a different layer. The two cannot be compared directly.

Once discovery and weaponization are this cheap, fast, and abundant, attackers find the next way in before humans can patch every hole. Stopping every intrusion at the perimeter is no longer possible.
Security is shifting from "build it so it can't break" to **"design it assuming it will be broken."** Zee takes responsibility for that "after."

---

## How it works — five layers

| Layer | What it does |
|---|---|
| 1. Behavior detection | Learns the normal behavior of every process and detects deviation. Reacts even to unknown techniques. |
| 2. Luring (with gatekeepers) | Routes suspicious activity into a convincing trap — designed never to ensnare legitimate staff or processes. |
| 3. Data poisoning | Swaps stolen data for marked decoys; the moment they're used, the attacker's infrastructure is revealed. |
| 4. Fake internal network | Makes the real network hard to distinguish, sharply raising the cost and time of reconnaissance. |
| 5. Long-term correlation | Connects slow, stealthy attacks (low-and-slow APTs) that unfold over months. |

---

## Coverage — what it does and doesn't protect

We do not publish numbers like "X% defense rate." Real environments aren't that simple, and exaggeration erodes trust. Instead, we state plainly what is and isn't covered.

**Covered:** post-intrusion anomaly detection / neutralizing data theft / exposing attacker infrastructure / nullifying reconnaissance / detecting stealthy long-term attacks / suppressing false positives.

**Not covered (honestly):**
- Preventing the intrusion itself (the role of perimeter defense — Zee complements, not replaces it).
- Network-layer counter-offense (C2 poisoning — not implemented yet; feasibility under review).
- Fixing/patching vulnerabilities (Zee is the detection-and-neutralization layer).

---

## Getting started

- No additional cloud subscriptions or external APIs required.
- Runs on the Python standard library only (fewer dependencies = smaller attack surface).
- Start with a detection-only "watch mode" in a few steps.

```bash
# Detection-only "watch mode" first
$ ./zee --watch
# Detailed steps coming soon
```

---

## Disclosure policy (hybrid)

We publish what can be public and protect what could be abused.

- **Public (this repository, MIT):** the overall mechanism, an architecture overview, and the underlying paper.
- **Applicant-restricted:** the full implementation, including the specific trap rules and conditions. Publishing these would let attackers evade them, so they go only to verified applicants.

Identity verification for the restricted part uses **a corporate registration number, employee ID, or company email address.**
**We never collect national ID numbers (My Number).**

How to apply: coming soon.

---

## Disclaimer

- Zee is currently a **proof-of-concept (PoC)**.
- Zee is **not a silver bullet.** It neither prevents intrusions nor detects every attack.
- Machine-speed offensive capability keeps advancing. As newer models become widely available, Zee itself will need vulnerability review and patching.
- Zee does not replace perimeter defense or patching operations — it is **one additional layer**.

---

## Paper

The mathematical basis of the design:
**Prime survival in affine Collatz dynamics (v20)**
→ https://github.com/KAMANOI/collatz-prime-survival/blob/main/paper/prime_survival_affine_collatz_v20.pdf

---

## Support

Zee is free. If it helps you, support via GitHub Sponsors is welcome (optional, zero platform fee).

---

## License

[MIT License](./LICENSE)

---

<sub>Japanese: [README.md](./README.md) · Installation, application process, and more coming soon.</sub>
