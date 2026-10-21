# Design: egress-rule drift line in `zee doctor` and G603 (key passed whole to a container)

Follows `agent-config-checks.md` rows A (light version) and C. Row B (swapping in real keys at an
exit proxy) is **not built**: it would make Zee hold real keys. Decision: representative, 2026-10-20 (item 196).

## A. `zee doctor` → "egress rules" (read-only)
Reads Zee's own egress-cut rules and compares with the cut record. **The block is confirmed authoritatively only on Linux** — nft via `nft -j list table inet zee_egress` (JSON, parsed structurally) and `iptables -S ZEE_EGRESS` with the OUTPUT jump read back. On **macOS** the single `pfctl -a com.apple/zee-egress-cut -s rules` read shows the anchor's rules but cannot confirm pf is enabled and its anchor referenced, so a loaded-looking pf block is reported **"unverified", never "present"** (the full pf confirmation — enabled state, anchor reference, sibling anchors — lives in `cut_egress._verify_egress` on the cut path, not here).

| Loaded rules | Cut record | Line |
|---|---|---|
| shape differs from what Zee loads | any | WARN (hand-edited / other software) |
| Zee shape | no open egress cut | WARN (left over or loaded outside Zee) |
| none | open egress cut | WARN |
| pf block loaded but not confirmable (macOS "unverified") | any | WARN (cannot confirm it is in force here) |
| unreadable (needs admin / tool missing — a missing tool is reported too) | any | INFO (run `sudo zee doctor`) |
| none | none, or Zee shape + open cut | OK |
| any | cannot be compared (no usable config, damaged record) | INFO |

**Deviation from the design table**: row A said "compared with the *approved allow-list*". No allow-list is stored (the egress approval engine is not wired in), so the comparison is with Zee's own cut shape and the cut record. When approvals are wired, add the allow-list comparison.
Limits: shape check only (nft: a rule that accepts with no match — regardless of counter/comment — makes it "unexpected"; an old nft without `-j` is treated as unreadable, never present) (not a proof of what traffic passes); rules from other software are not inspected; Windows is not checked; macOS pf is read but not authoritatively confirmed ("unverified", never "present"); unprivileged runs mostly print INFO (not measured on Linux in this branch — macOS only).

## C. G603 (MEDIUM)
`ENV`/`ARG` of a provider API key in a Dockerfile, `docker|podman|nerdctl run -e NAME`, or an entry under a compose `environment:` block of such a name (`ANTHROPIC/OPENAI/GEMINI/GOOGLE/XAI/MISTRAL/DEEPSEEK/COHERE_API_KEY`, `ANTHROPIC_ADMIN_KEY`, `AWS_SECRET_ACCESS_KEY`). Advice: give the sandbox only a short-lived, session-scoped credential.
Limits: variable name + line shape only; the value's origin is not followed; `.md`/`.txt`/test files and commented / "never …" lines are skipped; a renamed variable or `--env-file` is missed; one flag per file; a legitimate single-user container will also match (look here, not proof).
