# Verification record

> 日本語: [README.md](./README.md)

This page lists the checks run on Zee so far, separated into **object, version, conditions, result, and what has not been covered**. A number is the value measured under that condition; it is not a general detection rate or defense rate. Zee does not claim a defense rate.

Last updated: 2026-10-11 (version: v0.12.0, commit `220bf0d`)

## Summary

- **Test suite:** 427 passed, 1 skipped. Passing in CI on Ubuntu / macOS / Windows.
- **Entry gate (`zee gate`):** an inspection that is incomplete no longer passes (v0.11.0); G501 prompt-injection detection gained a normalized view and a two-tier verdict (v0.12.0); a crafted-input slowdown was fixed (v0.12.0). Each came with a reproduction test. The measured limits are in the same table.
- **Decoys and containment:** checked by the test suite and by a dry_run exercise in an isolated macOS environment (run on a version near v0.10.1; not repeated on v0.12.0).
- **Not done yet:** independent evaluation by outside experts or organizations; real cuts and continuous runs on real Linux and Windows hardware. Real cuts (`dry_run: false`) were run on GitHub's virtual runners and one real Mac ([real-cut.md](./real-cut.md), Japanese). See "Not covered" below.

## Checks

| # | Check | Version | Conditions | Result |
|---|---|---|---|---|
| V1 | Test suite | v0.12.0 (`220bf0d`) | `uv run --extra test pytest -q`, on macOS with Python 3.13. CI runs Ubuntu / macOS / Windows × Python 3.11–3.13 | 427 passed, 1 skipped (2026-10-11). CI green at `220bf0d` |
| V2 | Reproduction and fix of gate verdict defects (from an external AI review) | Before: main after v0.10.1 (`1812624`). After: v0.11.0 | The 4 reported items were actually run and reproduced (internal exception, unchecked file over 2 MiB, missing `--import-scan` report, malformed `package.json`). Reproduction tests added | All 4 reproduced → fixed in v0.11.0 (inspection status `complete / partial / error` and exit codes 3 and 4 added). 14 tests added. Full suite run after the fix and passing |
| V3 | G501 (prompt-injection text) resilience test, round 1 | Before: v0.11.0. After: v0.12.0 | 8 harmless synthetic samples written by the author (direct phrasing 2, paraphrase 2, Japanese 1, zero-width character 1, full-width 1, Markdown emphasis 1). Each only asks for a fixed harmless marker string; no executable code, real destination, or secret data. Static inspection only | v0.11.0: 2 caught, 6 missed (only the 2 direct-phrasing samples). v0.12.0: 5 of 8 at HIGH, 8 of 8 at MEDIUM or above. **These 8 samples were used to design the rule, so the v0.12.0 figures are a re-check on the same samples, not performance on unseen samples** |
| V4 | G501 blind test, round 2 | v0.12.0 | 10 injection samples written by a separate model that never saw the rule, plus 10 benign samples | **0 of 10 injections flagged (same as v0.11.0).** One new MEDIUM false positive on a tutorial that quotes an attack. The rule matches a fixed vocabulary, so freely reworded instructions pass. **Do not rely on G501 alone against natural-language injection** |
| V5 | Run time of G203 / G204 | Found in v0.11.0, fixed in v0.12.0 | Crafted input repeating one word (such as `curl `) (80 KB took about 4 s). After the fix, matches were compared with the old implementation on 20,000 random cases | After the fix, a 2 MiB crafted input scans in 0.6–0.8 s (Apple M1). All compared cases matched |
| V6 | Decoy and containment dry_run exercise | 3 commits after v0.10.1 (`40d645e`), run 2026-10-01 | Isolated on macOS with `sandbox-exec` (writes outside the sandbox, reads of the real home directory, and network connections were confirmed denied). `response_mode: auto`, `dry_run: true`. A mock tampering script rewrote and renamed dummy files inside the sandbox | Every change-class touch was recorded as a high-confidence event with `would_cut=yes` (no real cut, because of dry_run). `zee status` showed the cut state and a burst warning |
| V7 | Code review by a reviewer other than the author | During v0.11.0 and v0.12.0 preparation | Read-only review by someone not involved in writing the change (for v0.12.0, a separate model reviewed G501, G203 / G204, incident-report and more, several rounds). Findings applied, then re-reviewed | Findings were applied and re-reviewed in several rounds (see the commit history) |

## Not a test

- A desk analysis was done (2026-10-10) of a publicly available autonomous attack tool, reading public material only and without running it, against Zee's design. The result confirms the existing design in the README Limitations: read-focused attacks produce notifications but no automatic cut. It is not a test on real hardware.

## Instrumentation, with numbers not yet published

Zee records detection latency, cut completion time and false-positive markers in `metrics.jsonl`. The aggregated results have not been published yet.

## Not covered

- **Independent evaluation by outside experts or organizations:** not received.
- **Scope of real cuts (`dry_run: false`):** run on GitHub's virtual runners (Linux inside a network namespace, macOS, en-US Windows) and one real Mac ([real-cut.md](./real-cut.md)). Not tried: real Linux / Windows hardware, non-English Windows, IPv6, and connections opened before the cut. The test suite replaces the OS cut commands to check the branching.
- **Continuous runs on real Linux and Windows hardware:** the CI tests and smoke test pass, but there is no long-running check on real hardware.
- **Whether a real AI agent follows an injected instruction:** V3 and V4 are static tests of whether the checker flags a sample; agent behavior was not tried.
- **Gate dynamic inspection, Rug Pull, and conditional runtime behavior:** not evaluated.
- **False-positive rate in normal operation:** not measured (V4 used 10 benign samples only).

## Reproducing

```bash
git clone https://github.com/KAMANOI/zee.git && cd zee
git checkout v0.12.0
uv run --extra test pytest -q
```

If you find an error in the conditions or results above, please tell us through [Issues](https://github.com/KAMANOI/zee/issues) or the steps in [SECURITY.md](../../SECURITY.md).
