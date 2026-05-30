# Zee — Research

> 🌐 日本語: [RESEARCH.md](./RESEARCH.md)

This document describes Zee's **research direction**.
Research is described as research. It is not a product description, and it is not an effectiveness claim.

```
Status: Research-stage
Experimental. Intended architecture. Validation pending.
```

---

## CDS (Collatz Deception System)

```
Collatz Deception System (CDS)
An experimental deception architecture inspired by affine Collatz research.
The effectiveness of CDS has not yet been independently validated.
```

CDS is positioned within Zee as an **experimental research primitive for trap diversification**.
It is not a finished defense system. It belongs to states described as Research-stage, Experimental, Intended architecture, or Validation pending.

The long-form note is below ("CDS — Research Note"). Read it with the status above in mind.

---

## Affine Collatz research

```
Research explores whether affine Collatz dynamics may provide useful trap diversification properties.
This should not be interpreted as a cryptographic, security, or containment guarantee.
```

Affine Collatz research is treated as an **open question** about whether the dynamics provide useful trap-diversification properties (making it harder to identify what is a trap by reuse).
This is not a cryptographic guarantee. It is not a containment guarantee. The central evaluation question is whether an adversary's classifier requires more samples to reliably separate Zee-generated decoy activity from real activity.

Paper:
**Prime survival in affine Collatz dynamics (v20)**
→ https://github.com/KAMANOI/collatz-prime-survival/blob/main/paper/prime_survival_affine_collatz_v20.pdf

---

## Collatz Deception System (CDS) — Research Note

CDS is an experimental deception architecture inspired by the author's research into affine Collatz dynamics (Prime Survival in Affine Collatz Dynamics, v20, 2026). Its role within Zee is narrow: a trap-diversification primitive — a cheap, seed-regenerable source of varied, plausible-looking synthetic telemetry for deception environments.

Research question. Affine Collatz maps of the form f(p) = (a*p + b) / c define a large parameter family of integer trajectories that are inexpensive to compute, regenerable from a small seed plus parameters (a, b, c), and whose statistical behavior (trajectory length, growth/decay profile, value distribution) is characterized across map types in the v20 study. CDS investigates whether rotating these parameters per session or per deployment raises the cost of fingerprinting a deception environment — i.e., whether trajectory diversity increases the number of samples an adversary's classifier would need to reliably separate Zee-generated decoy activity from real system activity.

What CDS is not. CDS is not a cryptographic, security, or containment guarantee. The undecidability of the Collatz problem plays no defensive role here: an adversary is never required to decide whether a computation terminates, and CDS does not claim that any trap is undetectable or unavoidable. Affine Collatz output is structured, not random; with enough samples it can be clustered and classified. Parameter rotation therefore raises fingerprinting cost — it does not eliminate fingerprinting.

Honest comparison. For the narrow goal of cheap, diverse, plausible synthetic activity, conventional methods (seeded PRNGs, Markov models trained on real telemetry, perturbed replay of real logs) are mature alternatives and are often stronger for realism, since realism is best achieved by imitating real workloads. CDS is offered as one candidate generator, not the preferred one. Its only potential advantages are that it is cheap, seed-regenerable (minimal per-session state), and backed by an explicit theoretical understanding of its parameter-to-behavior mapping.

Status. Research-stage. Experimental. Intended architecture. The effectiveness of CDS has not been independently validated. Open evaluation questions: (a) whether parameter rotation measurably increases classifier sample complexity relative to a PRNG baseline; (b) the realism gap — whether a classifier can separate CDS telemetry from real telemetry with few samples; (c) defender-side cost per held session versus adversary resource actually consumed. Until these are measured, CDS should be read as a research direction, not a deployable defense.

---

## About CDS-Full

CDS-Full is an early-stage conceptual document where **proposal / concept / implemented / experimental / not implemented** elements are mixed together. To avoid confusion, every element in CDS-Full will be explicitly tagged with one of those categories when published. The main body of CDS-Full is not included in this repository at this stage.

---

## Caveat

All Research-section text in this repository should be read under the following assumptions:

- Effectiveness has **not been independently validated**
- Words like "guaranteed," "prevents," "stops," "unavoidable" are kept out of the Research section by policy
- What an implementation **intends** and what an implementation **proves** are not the same

Research is an open question.

---

→ For the Zee overview, see [README.en.md](./README.en.md).
