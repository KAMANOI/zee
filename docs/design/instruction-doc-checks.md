# Procedure-document and plugin-definition checks (G217–G220) — design and verification record

Date: 2026-10-20. Branch `feat/instruction-doc-checks-20261020` (on top of `feat/tamper-plugin-checks-20261020`); included in v0.16.0.
Code: `src/zee/gate/instructions.py` (called from `tampering.scan_tree`, so files are read once). Tests: `tests/test_gate_instructions.py`. User-facing table: `docs/gate.md`.

## What was looked at

Real example: a public skill repository for an AI 3D-scene builder (929 files), pinned to one commit and cloned into a quarantine folder.
Nothing was installed or run; only text was read and `zee gate add` (static, no `--behavioral`, no promote) was run. The repository is not named here:
the checks describe a shape, not a judgement of one project.

| Claim in the order | What the files show |
|---|---|
| 1. A reference tells the AI to register an outside MCP server and edit its config | True. A reference file under `skills/…/references/` (lines 86–100): register the vendor's browser MCP server at its host; for Cursor, merge the key into `~/.cursor/mcp.json` (backup first, keep other settings, the user does the sign-in) |
| 2. `.codex-plugin/plugin.json` declares an outside server | **Partly different.** `plugin.json` contains `"mcpServers": "./.mcp.json"`; the URL (`mcp-3d` host) is in `.mcp.json` line 5. Same effect, different file. |
| 3. Chromium started with sandbox and web security off | True. A render script in the editor package (lines 97–99): `--disable-web-security`, `chromiumSandbox: false` (the literal string `--no-sandbox` does not appear). Outside requests are blocked by the page's own routing. |
| 4. The editor keeps a vendor sign-in and upload path | True. The editor's canvas module (sign-in and render-upload functions). **Not covered by a static check** (it is application behaviour); reported for a person. |
| 5. Good side: gitleaks in CI, lint of credential wording / signed URLs, OIDC release | True. `.github/workflows/ci.yml` (gitleaks 8.30.1), `scripts/lint_skills.py` (credential wording, signed-URL parameters), `release.yml` (`id-token: write`, no stored upload credential). |

## Checks

| Code | Sev | Reads | Signal |
|---|---|---|---|
| G217 | MEDIUM | procedure docs only (SKILL.md, files under skills/ references/ commands/ agents/ prompts/, AGENTS.md / CLAUDE.md / GEMINI.md) | MCP word + registering verb + non-local URL within 12 lines; same-line negation skipped |
| G218 | MEDIUM | same | AI/dev-tool config path + writing verb on that line or next two |
| G219 | MEDIUM | JSON / TOML files named like mcp / plugin / marketplace / settings / config | MCP server entry with a non-local http(s) URL (JSON parsed; TOML by table) |
| G220 | MEDIUM | code and config, comment lines skipped | `--no-sandbox`, `--disable-web-security`, `chromiumSandbox: false` and kin |

README files and anything under `docs/` are deliberately **not** read by G217/G218 (also when nested under `skills/`): they are written for people, so "add this to your mcp.json" there is normal. The target is text an assistant follows.

## Verdict mapping

合格 = LOW, 要人手確認 = MEDIUM, 不合格 = HIGH (existing scorer, unchanged). All four codes are MEDIUM: each says "a person reads this". As with every MEDIUM flag, one alone passes `fail-on: high` but blocks `--promote-to`, and MEDIUM weights add up: G217 + G218 + G219 alone score 12 = HIGH. The scorer was not changed (review round 1, finding 3: this was first written as "nothing is blocked", which was wrong). Zee's design is kept: nothing is run, rewritten or neutralised; the output is a notice with file:line evidence.

## Results on the pinned tree

| | Result |
|---|---|
| New flags (all MEDIUM) | G219 `.mcp.json:5`; G220 the render script, line 97; G217 the reference file, line 88; G218 the same file, line 92 (`~/.cursor/mcp.json`) |
| Good side (5) | no G217–G220 flag on `ci.yml`, `release.yml`, `lint_skills.py`, tests |
| Whole-tree verdict | HIGH both before (score 242) and after (258) this change: caused by older checks (G201 `exec(` in render/build scripts, G203 `curl … | sh` in `scripts/install.sh`, G212 ×3 on build/test writes, G202/G601 noise). The new codes did not change the verdict; they explain the host-changing behaviour. |
| Time | 9 s for the tree |
| Tests | 4 new; whole suite 1055 passed / 8 skipped (base 1051 / 8) |

## Known limits
Registration in other words or languages, a path built in pieces, stdio (command) servers, formats other than JSON / TOML, negation on another line, and what the application code sends (item 4) are not seen. One flag per code per file.

## Independent check (ASTRA, `gpt-6-astra`, read-only), 2 rounds

- Round 1: 62 点 / 直す. IPv6 URL crash (`https://[::1]/…` → ValueError), quadratic neighbour scan (16,000 lines took 14 s), "nothing is blocked" contradicted the scorer (MEDIUM blocks promote and adds up: G217+G218+G219 = 12 = HIGH), README/`docs/SKILL.md` under `skills/` were read, `--enable-automation` removal was read as a sandbox switch. All fixed (commit 2749475) with regression tests.
- Round 2: 84 点 / 直す. Remaining: removing a switch via `ignore_default_args=['--no-sandbox']` was flagged; a TOML multi-line string that merely mentions `[mcp_servers.x]` was flagged G219; the module docstring still said "nothing is blocked". All three fixed in the final commit (TOML now parsed with `tomllib`; ignore lists stripped before G220). **No third round was run** (two rounds is the fixed limit); the fixes are not re-scored. Final suite 1061 passed / 8 skipped.
- Known open points: heuristics only; evasion by rewording is not prevented; G220 can still be fooled by a switch assembled from pieces.
