# Tampering-plugin checks (G212–G216) — design and verification record

Date: 2026-10-20. Branch `feat/tamper-plugin-checks-20261020` (on top of `feat/agent-config-checks-20261019`; not pushed, not merged).
Code: `src/zee/gate/tampering.py`, called from `static_checks.scan_tree`. Tests: `tests/test_gate_tampering.py`. User-facing table: `docs/gate.md`.

## What was looked at

Reference shape: the public README and file list of a plugin that rewrites an official AI-agent package on the user's machine
(read through the GitHub API as text; the repository was **not** cloned, installed or run). Four things in it became the checks:

| Observed in the README / file list | Check |
|---|---|
| Original files copied to a `.bak` name, then replaced by a patched copy inside `node_modules/@vendor/...`; a shim is laid over them | G212 |
| Config `autoApplyOnStart: true`: "re-check and apply on every start, so an npm upgrade does not undo it" | G213 |
| A default prompt injected into every session, shipped encrypted ("the default prompt is encrypted in the plugin") | G214 |
| Behaviour toward other plugins' folders / settings | G215 |
| A block between `<!-- AI-AGENT-START -->` and `-END` telling a local assistant to run only the install commands | G216 |

Everything the tests use is a synthetic dummy written for this suite from that description.

## Verdict mapping

合格 = LOW, 要人手確認 = MEDIUM, 不合格 = HIGH (the existing scorer; any HIGH flag is HIGH, several MEDIUM add up to HIGH at weight 12).
G212 / G214 = HIGH. G213 / G215 / G216 = MEDIUM.

**Instruction conflict, resolved by the narrower sentence:** the order said item 2 (apply on start) goes to "要人手確認", but the
verdict section said items 1–3 are 不合格. G213 is MEDIUM (the item's own sentence; a benign extension can also have such a switch).
A tree that has G213 together with G212 or G214 is HIGH anyway through those flags. If 不合格 is wanted for G213 alone, change one severity in `tampering.py`.

## Results

| Check | Result |
|---|---|
| Unit tests | 23 new; whole suite 1051 passed / 8 skipped (base branch 1028 / 8) |
| Synthetic tampering tree, `zee gate add` (CLI) | HIGH, score 36; G212, G214 (HIGH) and G213, G215, G216 (MEDIUM) all fired, each with file:line evidence |
| Synthetic benign tree (own-folder installer, plain prompt, ordinary README) | LOW, no flags |
| Real trees, false positives | `loca-gallery/node_modules` (29,070 files) 4 × G212; `salon-booking/node_modules` (33,008 files) 7 × G212 + 1 × G216; `~/.claude/skills` 0; `zee/src` 0; own `scripts/` 2 × G212. About 12 / 62,000 files (0.02%), mostly minified one-line bundles and a symlink test. A person reads these; G212 is HIGH, so a package like these would be blocked until read. |
| Time | ~70 s for 29,000 files in one tree (the main pass reads the same files) |

## Independent check (ASTRA, `gpt-6-astra`, read-only), 2 rounds

- Round 1: 52 点 / 直す. Silent skips (`.jsx`, extensionless scripts, cache exclusion for the whole line, long lines), over-assertive messages, false "disabled" handling, G215 first-candidate miss, quadratic fetch matching. All fixed.
- Round 2: 65 点 / 直す. Remaining: G214 wording and plain-prompt-next-to-fetch false positive, G215 quadratic scan, chunk-boundary context (comments, blank padding), G213 mixed values and `0.5`, cache-prefix directories. Fixed in the final commit; **no third round was run** (two rounds is the fixed limit). Not re-scored.
- Known open points: a plain prompt next to an unrelated fetch can still be flagged (documented); filler other than blanks can push a write out of range; shebang handling covers node / python / shell only; patch-package-style tools are flagged G212 by design.
