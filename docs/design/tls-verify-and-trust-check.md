# TLS verification switched off (G230)

Status: G230 is part of the entry gate (static check). `zee trust-check` is a prototype and is not part of this change.

## Why

2026-10-21: eMudhra intermediate-certificate keys leaked. Browsers were fixed within hours;
curl, Python, Node.js, Go and others trust a CA list copied onto the machine and mostly do not
check revocation, so the user has to update that copy (ITmedia 2026-10-21; Mozilla's own post
names neither the leaked certificates nor the root — the root name `emSign ECC Root CA - G3`
comes from ITmedia and is unconfirmed against a primary source).
Two questions follow for Zee: (1) does the code I am about to install turn certificate checking
off, so that none of this matters to it, (2) does a store on my machine still contain a root that is on the watch list (a root reported as withdrawn).

## 1. G230 — entry gate (static, `gate/tlsverify.py`)

- Flags a line that switches verification off: `rejectUnauthorized: false`,
  `NODE_TLS_REJECT_UNAUTHORIZED=0`, `strictSSL: false`, `verify=False`,
  `ssl._create_unverified_context`, `check_hostname = False`, `verify_mode = CERT_NONE`,
  `PYTHONHTTPSVERIFY=0`, `InsecureSkipVerify: true`, `curl -k/--insecure`,
  `wget --no-check-certificate`, git `http.sslVerify false`, npm `strict-ssl false`.
- **MEDIUM = "a person confirms"** (not HIGH): these are everyday shortcuts for local test servers.
  A MEDIUM flag passes `fail-on: high` but blocks `--promote-to` and adds to the score
  (same class as G213/G217-G220). Test/fixture/example paths: LOW.
- Scans code files (`.py .js .ts .sh .ps1 .go` ...) and a skill's procedure docs (SKILL.md, commands/, references/ ...: what the AI follows). README/docs are skipped (prose explains `curl -k`). Test/example paths are LOW — a rank, not a safety claim (a source can place code there). Comment lines are skipped. `verify=False` counts only
  within 3 lines of a network word (http, request, session, url, cert, ssl ...).
- A line over 2,000 characters (minified code) is read in overlapping 600-character pieces, not skipped; quoted keys (`"rejectUnauthorized": false`) count. For curl, a word that is the value of an option taking one (`-o`, `-H`, `-X`, `--output` ...) is not read as a flag. Files over 2 MiB are not read by this check (the main pass reports them as G910).
- Covers skills, packages and AI-generated code alike: the gate sees files, not their author.
- Does not run or change anything. Best-effort (I5): a wrapper, a runtime-built value or an
  unknown config key is not seen.

`zee trust-check` (read-only trust-store notice) is **not** part of this change; it stays a prototype (watch-list update path and primary-source confirmation of the root name are open).

## Design-principle check (containment only writes/deletes/renames; reads are notices; no sanitising)

| Principle | G230 | trust-check |
|---|---|---|
| Containment only for write/delete/rename | no action taken | no action taken |
| Read access = notice | a flag, no block by itself at the default `fail-on` | a printed notice |
| No sanitising | files are never rewritten | stores are never edited ("fix" belongs to the OS/package) |
| Network | none | none (Node and `security` run locally and read) |
| Over-claim | "a person confirms", not "insecure" | "not proof" printed on a clean result |

## Not done / open

- Wiring `trust-check` into `zee doctor`, and a list update path (`REVOKED_ROOTS` is a constant;
  a signed or versioned list is a later decision).
- No test with the real leaked chain: no chain was available, so "the client rejects the leaked
  intermediate" is untested.
- Measured false-positive counts are not published in this document.
