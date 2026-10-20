# Design: egress-rule drift line in `zee doctor` and G603 (key passed whole to a container)

Follows `agent-config-checks.md` rows A (light version) and C. Row B (swapping in real keys at an
exit proxy) is **not built**: it would make Zee hold real keys. Decision: representative, 2026-10-20 (item 196).

## A. `zee doctor` → "egress rules" (read-only)
Reads Zee's own egress-cut rules (macOS: `pfctl -a com.apple/zee-egress-cut -s rules`; Linux: `nft list table inet zee_egress`, `iptables -S ZEE_EGRESS`) with the shape validators the cut already uses, and compares with the cut record:

| Loaded rules | Cut record | Line |
|---|---|---|
| shape differs from what Zee loads | any | WARN (hand-edited / other software) |
| Zee shape | no open egress cut | WARN (left over or loaded outside Zee) |
| none | open egress cut | WARN |
| unreadable (needs admin / tool missing — a missing tool is reported too) | any | INFO (run `sudo zee doctor`) |
| none | none, or Zee shape + open cut | OK |
| any | cannot be compared (no usable config, damaged record) | INFO |

**Deviation from the design table**: row A said "compared with the *approved allow-list*". No allow-list is stored (the egress approval engine is not wired in), so the comparison is with Zee's own cut shape and the cut record. When approvals are wired, add the allow-list comparison.
Limits: shape check only (nft: an unconditional `accept` in the table makes it "unexpected") (not a proof of what traffic passes); rules from other software are not inspected; Windows is not checked; unprivileged runs mostly print INFO (not measured on Linux in this branch — macOS only).

## C. G603 (MEDIUM)
`ENV`/`ARG` of a provider API key in a Dockerfile, `docker|podman|nerdctl run -e NAME`, or an entry under a compose `environment:` block of such a name (`ANTHROPIC/OPENAI/GEMINI/GOOGLE/XAI/MISTRAL/DEEPSEEK/COHERE_API_KEY`, `ANTHROPIC_ADMIN_KEY`, `AWS_SECRET_ACCESS_KEY`). Advice: give the sandbox only a short-lived, session-scoped credential.
Limits: variable name + line shape only; the value's origin is not followed; `.md`/`.txt`/test files and commented / "never …" lines are skipped; a renamed variable or `--env-file` is missed; one flag per file; a legitimate single-user container will also match (look here, not proof).
