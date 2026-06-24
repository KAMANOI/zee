# Zee threat list (denylist) — format and contribution

Zee ships a community denylist in the repository and refreshes it from
GitHub. **No server, no central service** (invariants I1 / I4): the list
is plain JSON in version control, and every change is a reviewable pull
request.

## Two sources, merged

1. **Repo list** — `src/zee/gate/denylist.json`, shared by everyone.
2. **Local overlay** — `~/.local/state/zee/gate/denylist_local.json`
   (owner-only), grown by your own machine. When `zee gate audit` finds a
   Rug Pull, the drifted artifact's new hash is written here so you are
   protected immediately, before any upstream PR.

A match in **either** source is a HIGH finding (`G610` hash / `G611` name).

## Entry format

```json
{
  "hashes":  ["<sha256 of the artifact tree>"],
  "names":   ["<exact artifact name>"],
  "domains": []
}
```

- `hashes` — the sha256 Zee prints as `content_hash` / `sha256` for the
  malicious version. This is the precise, false-positive-free signal: it
  blocks exactly those bytes.
- `names` — use sparingly; a name match blocks every version by that name
  and can hit a later, fixed release. Prefer hashes.
- `domains` — reserved for a later phase (exfil / C2 destinations).

## Contributing an entry

1. Open a PR adding the entry to `src/zee/gate/denylist.json`.
2. In the PR description, link **public** evidence (an advisory, a write-up,
   a registry takedown). Do not paste secrets or victim data.
3. A maintainer reviews the evidence before merge.

## Integrity

The list's integrity rests on Git and GitHub review: a clone is verified
by commit history, and changes require a reviewed PR. Maintainers sign
release tags so a pinned release is verifiable. Per-entry cryptographic
signing is intentionally **not** implemented yet — it is tracked as future
work rather than claimed (invariant I5).
