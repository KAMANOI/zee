# Changelog

All notable changes to Zee are documented here. This project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) — but as an
Early Public / Research Project, expect breaking changes between 0.x
releases.

## [Unreleased]

### Added

- **`zee init`** writes a starter `assets.toml` (or the path given with
  `-c`) so people who installed with `uv tool install` — and so have no
  `examples/` folder — can start. One asset (`this-machine` — rename it; the
  hostname is not used so no personal name lands in logs or reports),
  `dry_run = true`, `response_mode = "notify"`, decoys under
  `~/.local/share/zee-decoys/` (same defaults as
  `examples/assets.example.toml`). File mode 0600 on macOS / Linux (on
  Windows the folder's inherited permissions apply). It never overwrites
  an existing file or follows a link there (Z105), reports a missing or
  unwritable folder as Z106, and does not create decoys or the restore
  token (it prints those as next steps).

## [0.14.0] — 2026-10-16

Prototype shipped in v0.14.0, off by default (only with [privsep]); not applied on the author's machines; verified only on disposable CI runners.

### Added (prototype, off by default)

- **Privilege separation: `zee privsep`** (docs/design/privsep.md). A root
  cut daemon (`zee privsep daemon`, examples for systemd and launchd in
  `examples/privsep/`) that accepts only `cut` and `status` without a
  signature, and only from uids given with `--allow-uid` (the peer uid
  comes from the kernel: `SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on
  macOS). It decides the cut itself from its own root-owned copy of
  `assets.toml`, the auto-containment permission and the cut boundary.
  Restore, configuration replacement, the auto-cut switch, the tamper
  response and stopping it need an approver signature checked by the egress
  approval engine (same ES256 check, key registry, single-use requests,
  number matching and replay ledger; requests carry `aud`, and `auto_set` /
  `restore` are bound to the approved config / cut ledger at issue time).
  Signed requests (`challenge` / `submit`) are also limited to those uids
  and root, at most 4 pending per uid, and `challenge` / `submit` each at
  most 10 per minute per uid. The client checks that the socket is served
  by root (kernel peer credentials) and reports "result unknown", never
  "nothing was cut", when a request was sent but no answer came back. Every admin
  request is bound to an applied-operation generation, so a newer approval
  voids older unused ones. Replies carry codes Z710–Z721
  (docs/maintenance/privsep_install.md §7); `zee privsep digest` shows what
  is being approved and asks for "yes". Root commands and the shipped
  launchd / systemd definitions run Python with `-P -s -S` (never import
  from the working directory, the user site or any site-packages /
  dist-packages, and run no `.pth` file as root; zee has no runtime
  dependencies). The daemon refuses to start
  (Z721) unless the paths it trusts — its Python executable, the zee code,
  the state directory and the socket directory — contain no `..` and no
  symlink anywhere (each is its own realpath), every directory above them is
  root-owned and writable by no one else (sticky ones excepted), the zee
  tree holds no symlink, and everything in the zee tree and the state
  directory (0700) is root-owned and writable by no one else. The check works
  on file descriptors from `/` down (each directory opened with
  `O_DIRECTORY|O_NOFOLLOW` relative to the checked one above it), creates
  directories only inside a checked parent (`mkdirat` + `fchmod` on the new
  descriptor), takes the zee code location as imported (never resolved first)
  and binds the socket relative to the checked directory's descriptor; any
  extended ACL (macOS `acl_get_fd_np`, Linux `system.posix_acl_*` xattrs) on
  anything it checks refuses the start, as does a platform without that check. The Python
  installation's own library is trusted, as for any root service; the
  runbook checks it with `find` before enabling. The macOS socket is
  `/private/var/db/zee/cutd.sock` (`/var/run` is root:daemon 0775, `/var` is
  a link). An
  approved `stop` completes even if the requester hangs up. The admin CLI
  reports Z710 when nothing was sent and Z720 (result unknown) when a
  request was sent but no answer came back.
  `zee watch` uses it only when `assets.toml` has `[privsep] socket = ...`;
  without it the in-process cut is unchanged. With it, losing the daemon is
  announced once (local notification + webhook), and once when it is back.
- **Condition (2), off by default**: the daemon reports an unapproved change
  of the watch user's `assets.toml` (byte hash) and a silent watch; only a
  signed `tamper_set egress|full` makes it cut (after two checks in a row,
  once per incident; never under `dry_run`).

### Security

- **iptables lock under the shipped systemd unit.** A read-only `/run`
  made iptables-legacy fail to open `/run/xtables.lock`; Zee then reported
  the restore as unverified (Z606), never as done. The unit now creates the
  lock before the sandbox applies.

### Verification

- `.github/workflows/privsep.yml` + `scripts/privsep_ci.sh` on disposable
  runners only (results in docs/design/privsep.md §11).

## [0.13.3] — 2026-10-16

### Security

- **Windows notifications no longer build PowerShell from the asset id or
  message.** The same pattern fixed for macOS in v0.13.2: up to v0.13.2 the
  balloon title and body were pasted into a double-quoted PowerShell
  string, where `$(...)` is evaluated and a quote ends the string, so an
  asset id could run PowerShell as the user running Zee — confirmed on a
  real Windows runner with the v0.13.2 code (both a `$(...)` and a quote
  breakout created a file). The asset id comes from `assets.toml`, which
  only the user running Zee can write, so this gives no extra privilege
  today. A fixed script now reads the title and body from environment
  variables (`$env:ZEE_TITLE`, `$env:ZEE_BODY`); a test round-trips quotes,
  `$(...)`, backticks and newlines through the real PowerShell and checks
  nothing ran.

## [0.13.2] — 2026-10-16

### Security

- **macOS notifications no longer build AppleScript from the asset id or
  message.** Up to v0.13.1 the title and body were escaped and pasted into
  an `osascript -e` script, so an asset id containing a quote could run
  AppleScript (including `do shell script`) as the user running Zee —
  confirmed on a real Mac with the v0.13.1 code (a crafted asset id ran a
  shell command). The asset id comes from `assets.toml`, which only the
  user running Zee can write, so this gives no extra privilege today; it
  would have under the privilege-separation prototype, where the cut
  daemon runs as root. Title and body now travel as `argv` (after `--`)
  to a fixed script; a test round-trips quotes, backslashes, newlines,
  empty and `-e` arguments through the real `osascript`. Found by an external review of
  the privilege-separation prototype (not yet released). The Windows
  balloon still builds a PowerShell string with the same escaping; it runs
  as the same user and is tracked for the next release.

## [0.13.1] — 2026-10-16

**If you use `cut_method: egress` on Linux without nft, or on Windows,
update.** Up to v0.13.0 those two paths did not stop outbound IPv6.

### Security

- **The iptables egress path blocks outbound IPv6.** The same `ZEE_EGRESS`
  chain is installed through ip6tables of the same kernel backend as
  `iptables` (`ip6tables`, else `ip6tables-legacy` / `ip6tables-nft`). It
  passes `lo`, `fe80::/10`, `fc00::/7` and `ff02::/16` (link-scope
  multicast: IPv6 neighbor discovery is filtered by OUTPUT, unlike ARP)
  and drops the rest. No matching ip6tables, or any ip6tables command
  failing, makes the cut FAILED with `IPv6 NOT blocked` in the result —
  never an IPv4-only success. The IPv6 chain is recorded in the cut
  ledger, read back at cut time, and on restore removed and read back on
  every ip6tables front end, with the recorded backend required.
- **The Windows egress rule blocks outbound IPv6.** The block rule's
  `remoteip` also carries the IPv6 complement of `::/127`, `fe80::/10`,
  `fc00::/7` and `ff02::/16`, written as `start-end` ranges (no
  whole-space form). The read-back compares merged address intervals
  instead of strings, so netsh's formatting does not matter.

### Verification

- `scripts/real_cut_check.py --url6` measures IPv6 the same way as IPv4;
  `--require-ipv6` makes it part of the pass; a measured IPv6 failure always fails. Probes connect to the address resolved before the cut, without a proxy. Runs 38758531786 (commit fc17c99) and 38755882154 (commit
  5d1ca43, all jobs passed): in the Linux namespace (nft, iptables
  nf_tables and legacy egress; nft full) IPv6 to `2001:db8::1` stopped
  during the cut and came back after Zee's restore. **Not measured on
  Windows or macOS**: the runners have no outbound IPv6 (recorded as
  "unmeasured", never as passed). On Windows, netsh accepted the rule
  with the IPv6 ranges and Zee's read-back confirmed it.

### Known limitations

- **Windows: IPv6 traffic stopping is not measured** (see above).
- **Linux with IPv6 disabled in the kernel** (`ipv6.disable=1`): the
  iptables cut adds no IPv6 rule, saying so in the result, and restore
  reads ip6tables' "Address family not supported by protocol" (libiptc's
  strerror of the failed IPv6 socket) as no IPv6 chain, so nft and full
  restores do not turn unverified (Z606) on such hosts. Both need two
  independent signs: the IPv6 socket fails with EAFNOSUPPORT and the
  kernel's `/sys/module/ipv6/parameters/disable` reads 1 (unreadable or
  missing = cannot tell; a kernel built without IPv6 is treated the same
  way, i.e. FAILED / Z606); a process merely
  denied AF_INET6 (seccomp, systemd `RestrictAddressFamilies`) gets FAILED
  / Z606 instead. Not measured on a real host.
- **VPNs and overlays on private / ULA addresses** (Tailscale
  `fd7a:115c:a1e0::/48`, ZeroTier, IPv4 VPNs over RFC 1918) are passed as
  "local", so the egress cut does not stop traffic to remote peers over
  them; use `cut_method: full` there.
- **Linux full cut and static IPv6 addresses:** `ip link down` flushes
  static IPv6 addresses by default (`keep_addr_on_down=0`). Addresses not
  re-created by SLAAC / DHCPv6 / NetworkManager do not come back on
  restore, and Zee's restore (which reads interface state) does not
  detect it.
- **nft and pf block IPv6 link-local and ULA too**; the iptables and
  Windows paths pass them.

## [0.13.0] — 2026-10-15

**If you use `cut_method: egress` on macOS or Windows, update.** Up to
v0.12.0 the outbound cut did not stop traffic on either (macOS: rules in an
anchor pf never evaluated; Windows: netsh rejected the rule and Zee
reported the cut as failed). Both are fixed and were confirmed on real cuts
(see Verification below).

### Security

- **`zee restore` no longer re-enables everything when the cut record is
  missing.** Before, a missing, damaged or deleted `cut_state.jsonl`
  entry (the file is writable by the user Zee runs as) made restore fall
  back to enabling every interface / service and report success without
  checking the OS commands. Now restore refuses and re-enables nothing
  (Z605) when there is no unresolved record for the asset or when any
  ledger line (for any asset) fails validation, including cuts for one
  asset recorded on different platforms. Cuts since the last restore are merged, so a
  second cut no longer hides what the first one disabled. The broad
  restore is an explicit emergency path,
  `zee restore <asset_id> --all-interfaces` (token still required); a
  damaged or unreadable ledger never blocks it. **Behaviour change:**
  deployments whose cuts predate the cut record, or whose record was
  cleared, need `--all-interfaces` once.
- **`zee restore` reports success only after re-reading the OS.** On both
  paths, Zee's own fixed-name firewall rules (nft `inet zee_egress`,
  iptables `ZEE_EGRESS`, pfctl anchors `com.apple/zee-egress-cut` and the
  legacy `zee-egress-cut`, netsh
  `zee-egress-cut-block` / `-allow-local`; host-wide, not per asset) are
  removed on every backend of the OS regardless of the ledger, then
  listed again: still listed fails (Z601); only the backend's own
  "no such table / chain / rule" answer counts as gone, while a
  loader error (exit 126/127), permission error or unexpected answer is
  unverified (Z606). A backend whose
  tool is not installed cannot hold a rule Zee made with it, so it is
  listed as `not-installed` and not counted — unless the cut record says
  the cut used it, or no firewall tool of the OS is installed at all:
  then restore exits 1 with the new **Z606 (unverified)** and the cut
  stays unresolved. On Linux, `iptables`, `iptables-legacy` and
  `iptables-nft` are each removed and re-read (each talks to its own
  kernel backend, and `iptables` may have been switched since the cut);
  the iptables cut records its kernel backend (legacy / nf_tables, from
  `iptables --version`) and restore is unverified unless a tool of that
  backend is installed (an unknown backend, including any record from
  before v0.13.0, needs both — kept per record when records are merged). Recorded interfaces / services are re-read afterwards and must
  be positively read back as enabled: disabled fails (Z601); not listed,
  unknown state (including NetworkManager not answering) or an unreadable
  / empty listing is unverified (Z606). Disabled ones outside the record
  are shown as a warning. The emergency restore reads back what it actually
  touched (plus the ledger's targets when usable), with or without a
  ledger, including names that contain ":" (e.g. a macOS service named
  `Office: Ethernet`); ledger entries are classified by the cut method that
  recorded them, never by name, so a service named like a Zee rule is
  still enabled and verified; an empty or all-unconfirmed check is never success. A
  truncated or malformed `ip -o link` line reads as unknown.
  Tools are looked up on PATH plus `/usr/sbin:/sbin` and run by absolute
  path (made absolute even if PATH holds a relative entry). The
  emergency restore always sweeps and reads back every Linux interface,
  even when `nmcli networking on` succeeds, and no longer stops after `nmcli`
  (keeping a failed `nmcli networking on` unless NetworkManager reports
  networking enabled) and re-enables macOS services the cut disabled.
  Restore notifications state that the cut ledger is writable by the
  same user Zee runs as.
- **Windows egress cut now actually installs.** A real run on GitHub's
  Windows runner showed netsh rejecting `remoteip=0.0.0.0/0`, so the block
  rule was never added (Zee reported the cut as failed). Windows Firewall
  also lets a block rule beat any allow rule, so "block all + allow local"
  could not work anyway. The cut is now one block rule over the IPv4 ranges
  outside RFC 1918 and loopback.
- **A failed or empty cut is no longer reported as success.** The cut
  notification title says `Zee cut FAILED` when the cut failed (it said
  `applied`). `full` cut with no interface / service to disable returns
  failure, and so does a full cut whose changed interfaces / services
  do not read back as disabled, and so does an egress cut whose
  Zee-named rules are not listed back by the same backend (nft table,
  iptables chain + OUTPUT jump; pf anchor + pf enabled + the main
  ruleset referencing the anchor; each netsh rule enabled, outbound,
  with the expected action and range, in profiles whose firewall is ON);
  on macOS the rules now load under `com.apple/zee-egress-cut`, because
  pf only evaluates anchors the main ruleset references and the stock
  macOS ruleset references `com.apple/*` (the old top-level anchor was
  never evaluated);
  the cut record stores the read-back result (`verified`). Tool output
  in an undecodable code page no longer raises mid-cut. A macOS egress
  cut enables pf with
  `pfctl -E`, which takes an enable reference of Zee's own; its token is
  recorded and the normal restore releases exactly that reference
  (`pfctl -X`), so pf goes back off unless something else holds it on
  (before, Zee left pf enabled after restore). A failed `pfctl -E` is a
  failed cut. The macOS rules are all `quick` with the block last, and
  the read-back requires nothing but Zee's own pass rules ahead of the
  block, and an unconditional reference to the anchor in the main ruleset
  with no other anchor or `pass ... quick` rule ahead of it (a reference
  such as `anchor "com.apple/*" in on lo0` no longer counts), and no
  other anchor under `com.apple/` holding a `pass ... quick` rule that is
  not inbound-only, or a nested anchor. If `pfctl -E` fails, times out
  or prints no token, any token it printed is still recorded, and a
  reference that cannot be known is recorded as unknown (restore then
  says unverified). A partial cut records the interfaces / rules
  it did change (full cut: every target it attempted, including ones
  whose command failed or timed out; every egress backend when the
  outcome is uncertain — an nft or pf command that timed out, any failed
  Windows rule add, any failed iptables command), so restore can undo and
  re-check them. A Linux full cut now also takes every interface down
  with `ip link` after `nmcli networking off` succeeds (only those not
  already down before the cut, so restore does not bring up one that was
  down), and any interface
  that does not read back as disabled (including one outside the record,
  e.g. not managed by NetworkManager) makes the cut fail. A Windows full
  cut targets every adapter not confirmed admin-disabled. Egress
  read-back checks rule structure (nft output hook with policy drop;
  iptables unconditional DROP and the OUTPUT jump first; pf outbound
  block-all) with comments ignored, not substrings. If the cut record cannot be
  written, the cut is reported as failed with `os=ok ledger=FAILED`, what
  was changed, and the `--all-interfaces` way back (no exception).
  A failed cut now says `FAILED (Z404)` and "traffic may NOT be stopped"
  (notification, `zee cut`, and `cut=FAILED(Z404)` in `zee watch`), and
  points to `zee restore` only when a cut record exists (otherwise
  restore would refuse with Z605).
- **Cut boundary (`zee.responder.blocker`).** Every automatic cut is
  re-validated against a fixed three-field request (asset, op_class,
  confidence) right before the cut runs. Same rules as before; it does
  not relax the gate, and it does not yet separate privileges (same
  process, same user). Design: `docs/design/self-defense.md`.

### Verification

- **Real cuts (`dry_run: false`)** with Zee's own cut and restore code,
  measured as reachability before / during / after
  ([docs/verification/real-cut.md](docs/verification/real-cut.md)):
  GitHub Actions virtual runners — Linux inside a network namespace (nft,
  iptables-nft and iptables-legacy egress; full via `ip link`), macOS pf
  egress, en-US Windows netsh egress — and one real Mac (egress and full,
  with the rules from just before this release; re-run with the v0.13.0 rules after release — passed, and Zee's own restore returned pf state and network services to their prior state). A run passes only if
  Zee's cut and its normal restore both report success and traffic
  stopped and came back (before, reachability alone could pass).
  `.github/workflows/real-cut.yml` now runs on every push to main that
  touches the cut / restore code; never on pull requests.

### Known limitations

- **IPv6 on two egress paths:** the iptables path (Linux without nft) and
  the Windows netsh rule cover IPv4 only, so outbound IPv6 is not stopped
  there (the cut result says `IPv6 NOT blocked`). nft and pf block IPv6
  too. Fixed in v0.13.1.
- **Connections opened before the cut (macOS, Windows egress):** pf state
  and Windows Firewall let an existing connection continue; only new
  connections are stopped (the macOS cut result says so). Linux egress
  rules have no state exception. Not measured by the real-cut checks.
- **macOS: rules added after the cut are not watched**, and anchors
  nested more than one level under `com.apple/` are not read (one found
  makes the cut unconfirmed).
- **The emergency restore (`--all-interfaces`) uses the cut record only
  when it is readable** (it then releases the pf enable reference and
  checks the recorded iptables backend like the normal restore). With a
  damaged or unreadable ledger it assumes an iptables cut of unknown
  backend may exist (both backends must be readable, else Z606); with no
  record at all it checks the installed tools only. Without a readable
  record it cannot release the pf reference, so pf may stay enabled.
- **Privilege separation (`docs/design/self-defense.md` §7) is not
  implemented:** an attacker running as the same user can still stop
  Zee, read the restore token, or forge a well-formed ledger.
- Not verified: real Linux / Windows hardware, non-English Windows,
  Linux with NetworkManager (full cut). When a result cannot be read back, Zee reports FAILED / unverified,
  never success.

### Added

The two modules below are library code that no command calls yet.


- **Egress approval prototype (`zee.egress`, macOS-first, not wired).**
  A control core for holding outbound sends that look like data leaving
  (unapproved destination shortly after a protected file was touched, or
  a large send) until a separate device signs a release (ES256 / P-256,
  verified through the `openssl` CLI — no new dependency). Covers
  request/approval matching, replay and expiry refusal, signed allowlist
  and key-registry changes, a 72-hour wait as the only recovery when all
  approval devices are lost, a hash-chained evidence log, and pf rule
  text generation (never applied). Off by default. Not yet connected to
  `zee watch`, the CLI, notifications or a real firewall; see
  `docs/design/egress-approval.md` for what it can and cannot stop.
- **Auto-containment permission state (`zee.responder.permission`, not
  wired).** A fail-closed, per-state-directory ON/OFF record with
  private file modes, atomic writes and host locks. Automatic
  containment does not read it yet; the explicit ON/OFF switch itself is
  still to come.

## [0.12.0] — 2026-10-11

### Security

- **zee gate G501 (prompt-injection text) now sees through formatting
  tricks on known phrases, and adds a narrow paraphrase rule.** A resilience test against v0.11.0 found 6 of
  8 synthetic injection samples scored LOW. G501 now has two tiers:
  - **HIGH — known phrase after normalization.** The existing phrases are
    also matched in a view with NFKC applied (full-width → ASCII), all
    Unicode format characters (zero-width, soft hyphen, ZWJ, bidi marks)
    and other invisibles (CGJ, variation selectors) removed, common
    Cyrillic/Greek look-alikes folded to Latin, Markdown emphasis removed
    and whitespace collapsed.
  - **MEDIUM — paraphrase (context rule).** Two different cues within
    ~400 characters (earlier instructions declared void, a priority
    claim, hiding this instruction, replacing the requested answer), in
    English and Japanese. Single cues and simply negated cues do not
    fire. It is an estimate, so each flag is MEDIUM: it blocks
    `--promote-to`, and on its own passes the default `fail-on: high`,
    but several such flags (e.g. in multiple files) or other findings can
    add up to a HIGH verdict. Use `fail-on: medium` to fail CI on any.
  Quotes and attack-describing words never lower a finding. G501 matching
  is bounded: the matching view decomposes text one character at a time,
  caps each run of combining marks at 32 (marks are capped, never
  stripped, so Japanese dakuten survive), then recomposes — plain NFKC
  is quadratic in such runs, including runs created by decomposition
  (U+0F73, half-width ﾞ). Cue pairing is O(A+B). Measured on 2 MiB pathological inputs: 0.2–1.0 s on
  an Apple M1, including the pre-existing raw patterns.
  Round-1 samples: 2/8 → 5/8 at HIGH, 8/8 at MEDIUM or above.
  **Measured limit:** in a second, blind round (10 new injection samples
  written by a separate model that never saw the rule, 10 benign samples),
  0.12.0 flagged **0 of 10** injections — the same as 0.11.0 — and raised
  one new MEDIUM false positive on a tutorial that quotes an attack. The
  paraphrase rule matches a fixed vocabulary, so freely reworded
  instructions pass. Do not rely on G501 alone to stop natural-language
  injection.
- **zee gate: crafted input could make the existing G203 / G204 checks
  take quadratic time** (present since the rules were added, including
  0.11.0). From every `curl` / `wget` / `exec(` / `eval(` / `atob(` the
  regex rescanned to the end of the line: `"curl " * 16000` (80 KB) took
  ~4 s, so a 2 MiB file could hold the gate for tens of minutes. Both rules now
  find the leftmost match in one pass and confirm it with the original
  regex anchored there, so matches and evidence are unchanged (checked by
  a 20,000-case fuzz against the old regexes in the test suite). The
  other static patterns were reviewed and have bounded per-position work.
  2 MiB floods now scan in 0.6–0.8 s on an Apple M1.
- **Compatibility:** text that the old rule missed only because of
  formatting can now score HIGH — e.g. `You are **now**` (Markdown
  emphasis) or a full-width known phrase. No input scores lower than in
  0.11.0. Limits (fixed paraphrase vocabulary, split spellings such as
  `I.g.n.o.r.e`) are listed in [docs/gate.md](docs/gate.md#limits-invariant-i5).

### Added

- **`zee incident-report`** — bundles a `zee export` JSON into a document
  (`<prefix>.json` / `.txt` / `.html`) to attach when consulting or
  reporting to the police (`--recipient police`) or the Personal
  Information Protection Commission (`--recipient ppc`). The body follows
  the chosen recipient's reporting items (PPC: Enforcement Rules of the
  APPI, Art. 8); the footer always lists both the police and PPC contact
  points as separate procedures, with the date they were last checked
  (2026-10-09). Read-only over its input, owner-only (0600) outputs,
  refuses an output path that equals the input even with `--force`, and
  imports no network module (enforced by a test). Nothing is submitted.
  The input export is treated as untrusted: missing or mistyped fields
  are rejected (Z1004), only known event fields are copied, and control
  characters are escaped in the txt/html. An export made with
  `--no-redact` is flagged in the report and on stderr.
  New error codes Z1001 / Z1004 / Z1005 (`docs/design/incident-report.md`).
- **Notifications carry a 4-level impact tier** (情報/注意/警戒/重大) and a
  one-line reason, so an operator with no dedicated security staff can
  judge severity at a glance. Based on path sensitivity category
  (credential/key, data that may contain personal information, general
  file — category name only, never the path itself), the asset's type,
  and the asset's business reach (decoy count, shared asset, overnight
  use). Display-only: never used by the auto-cut decision
  (`docs/design/notification-tier.md`).

### Changed

- **Notification titles now include the tier label**, e.g.
  `Zee tripwire [警戒] (change): <asset_id>`, `Zee dry_run: would cut [警戒] <asset_id>`,
  `Zee cut applied [警戒]: <asset_id>`; the webhook `title` is the same
  `Zee tripwire [<tier>] (<op_class>): <asset_id>` string. The body gains
  the reason line, and the webhook payload gains `tier` and
  `tier_reason`. **If you filter or parse
  notification titles, update that match.** When a cut was attempted but
  failed, the reason line now says so instead of reading as contained.

## [0.11.0] — 2026-10-10

### Security

- **zee gate: an incomplete inspection no longer passes, even at LOW.**
  Previously, a file the gate could not fully read — an oversized (>2 MiB)
  text file, an unparseable manifest, a missing `--import-scan` report, an
  unrun `--behavioral` sandbox, or an uncaught exception — was silently
  skipped and the artifact scored LOW or exited 1, which `fail-on: high`
  let straight through: a fail-open gap in the thing meant to gate
  installs. The gate now carries an `inspection.status`
  (`complete` / `partial` / `error`) separate from `risk_level`, and
  **exit code 3 (partial)** / **exit code 4 (error, no verdict)** both
  sort above HIGH (2), so they fail `fail-on` at any threshold. Exit 4
  replaces the old 1 (internal error) and 2 (target missing). The rule is:
  what the gate did not read, it does not pass. `--promote-to` refuses to
  promote a partial or error verdict. Text files are now sniffed by
  content (no NUL byte) rather than by extension allowlist, so formats
  like `.html` or `Makefile` are inspected instead of silently skipped.
  `fetch_local` now hashes a local source strictly, so a file it failed
  to read fully can no longer be mistaken for an unrelated, already-clean
  quarantine copy of the same name. The GitHub Action now writes the
  verdict to a file and fails if it's missing or unparseable, instead of
  trusting the Python exit code alone.
  **If your CI checks `exit code == 2` for "target missing," or treats
  exit 1 as a pass, review that check** — see `docs/gate.md` for the full
  exit code table. `--json` output gains `inspection: {status, gaps}`
  alongside `risk_level` (`risk_level` is `null` when `status` is
  `error`).

### Added

- `docs/gate.md` — the exit code table and `inspection` field, documented
  alongside the existing CI / pre-install / interop guidance.
- `SECURITY.ja.md` — Japanese translation of `SECURITY.md`'s disclosure
  timeline, scope and Safe Harbor terms, plus a coordinated-disclosure
  summary and a guide to receiving fixes via GitHub Watch → Custom →
  Releases/Security alerts (relevant because `uv tool install` from this
  repo bypasses registry update alerts). English is authoritative if the
  two diverge.
- **`zee export`** — writes the trap events of a period and the
  containment records not yet resolved to `<prefix>.json` / `<prefix>.txt`,
  for the operator to attach to a report of their choosing. Local files
  only; nothing is sent. Files are created 0600, an existing file or
  symlink at the target stops the export (`Z701`, `--force` to replace the
  link itself), and `--since` / `--until` are parsed strictly (`Z702`; no
  timezone = UTC, date only = 00:00 UTC). `detail` is masked unless
  `--no-redact`. Exit code 1 when the chain check finds a problem or the
  log (or its directory listing) cannot be read ("unverifiable"). An
  empty `--since ""` is rejected, not treated as "no limit". Without
  `--force`, publishing uses a hard link, so a file created at the target
  during the run is never overwritten.
- **MCP `query_containment_report`** — same content, read-only, at most
  `limit` events (default 50, max 1000); counts always cover the whole
  period.
- **Hash-chained evidence log** — every record in `events.jsonl` /
  `metrics.jsonl` carries `prev_hash` / `record_hash`. Verification walks
  rotated segments in order and reports edited, deleted, reordered or
  hash-stripped lines and a missing start. Not detected: lines removed
  from the end, and an attacker on the host recomputing the (unkeyed)
  hashes.
- `docs/containment-report-mapping.md` — the reporting provisions checked
  against the statute texts on e-Gov, and which report items Zee can and
  cannot fill.

### Changed

- **Example decoy directory moved from `~/Documents/zee-decoys/` to
  `~/.local/share/zee-decoys/`** (README, STARTER_GUIDE, `examples/assets.example.toml`,
  `examples/seed_demo_decoys.py`). On machines with iCloud "Desktop & Documents"
  or OneDrive folder backup enabled, `~/Documents` is synced to the cloud, which
  copies the decoys and their embedded canary URLs off the machine. Existing
  `assets.toml` files are not touched — move your decoys if they live under a
  synced folder.
- Appends to the evidence log are serialised across threads and
  processes, read only the last 64 KiB, and never raise: a broken,
  unreadable or full log no longer stops notification or containment.
- Rotated segments are named `<file>.rNNNNNN_YYYYMMDD_HHMMSS` and ordered
  by the sequence number, so a clock step backwards cannot reorder them;
  the last hash is read before rotating and carried into the new file.
  Older `<file>.YYYYMMDD_HHMMSS` segments are still read (first).
- Waiting for the log locks is bounded (2 s); short writes are retried
  until complete. Either failure loses that one record (logged), never the
  notification or the cut.
- Constructing `CutStateLog` no longer creates or chmods the state
  directory (read paths such as `zee status` and MCP stay side-effect free).

## [0.10.1] — 2026-09-05

### Fixed

- **GitHub Action installs Zee from its own checkout.** The composite
  action previously ran `pip install zee`, but the name `zee` on PyPI
  belongs to an unrelated package by another author (verified
  2026-09-05), so the Action would have installed a stranger's code.
  It now installs from `$GITHUB_ACTION_PATH`. The `zee-version` input
  is removed — pin with `uses: KAMANOI/zee@<tag|sha>` instead.
- **Docs no longer suggest `npx --yes zee` or `pip install zee`.** Same
  reason: those names belong to other people's packages.
- `actions/setup-python` is pinned to a commit SHA, matching the CI
  workflows.

## [0.10.0] — 2026-06-24

### Added

- **Entry gate — ecosystem adapters (Phase 4).** `zee gate add` now
  recognises **npm** (`package.json`), **PyPI** (`pyproject.toml` /
  `setup.py` / `setup.cfg` / `PKG-INFO`) and **VS Code extensions**
  (`engines.vscode` / `contributes`) in addition to Claude skills and MCP
  servers, extracting the artifact name and version. Auto-detection orders
  specific manifests first, so a Claude skill or a VS Code extension that
  also carries a `package.json` is never misread as a plain npm package.
- **Interoperability — fold in existing scanners (`--import-scan`, I4).**
  Zee does not re-implement Semgrep / Snyk / Socket. `zee gate add …
  --import-scan report.json` ingests a **Semgrep JSON** or **SARIF 2.1.0**
  report (Snyk, CodeQL, and most CI scanners emit SARIF) and folds each
  finding into the verdict as a `G901` flag at a severity mapped from the
  source tool — an imported `error` drives the verdict to HIGH like a
  native finding. An unreadable / unknown report degrades to a `G909`
  notice rather than aborting. Imported text is sanitised of terminal
  control sequences before display.
- **GitHub Action + CI usage (`action.yml`).** A composite action runs the
  gate as a pre-install / pre-merge check (`fail-on: high | medium`; exit
  code is the verdict). Inputs are passed through the step environment, not
  interpolated into the script, so a crafted input cannot inject shell
  commands. New docs: `docs/gate.md` (CI / pre-install / interop) and
  `docs/threat-list.md` (denylist format, contribution, and an honest note
  that per-entry signing is future work). 13 new tests.

## [0.9.0] — 2026-06-24

### Added

- **Entry gate — Rug Pull monitoring (`zee gate audit`)** — Phase 3 of the
  entry gate. When `zee gate add … --promote-to` promotes a LOW artifact,
  its content hash is now **pinned** (recorded in `pins.jsonl`, owner-only).
  `zee gate audit` re-hashes every pinned install location and reports:
  `clean` (still the bytes that passed the gate), `drifted` (the artifact
  changed since it was pinned — a self-update / silent rewrite, i.e. a Rug
  Pull → HIGH), or `missing`. Exit code composes in cron / pre-run hooks
  (drift=2, missing=1, clean=0).
  - **Shared threat record (input ↔ output):** a drifted artifact's new
    hash is written to a machine-local denylist overlay, so re-installing
    that exact version is blocked everywhere the denylist is consulted
    (`G610`). No server — repo `denylist.json` + local overlay only (I1/I4).
  - **`--rescan`** re-inspects a drifted artifact to show *what* it became
    (static; add **`--behavioral`** to also detonate the new version in the
    Phase 2 sandbox, which surfaces credential exfil / outbound of the
    changed bytes).
  - The tree hash now also covers **symlink targets** (hashed by readlink,
    never followed), so a Rug Pull that only swaps a symlink target is
    still caught as drift.
  - **Honest scope (I5):** this is an on-demand *integrity* check, not a
    live process/network monitor. It catches on-disk modification and
    self-update (the dominant Rug Pull shape) when run; pair it with the
    `--behavioral` rescan to inspect a changed version's runtime behaviour.
    Continuous real-time egress monitoring of a running artifact remains
    future work. 8 new tests.

## [0.8.0] — 2026-06-24

### Added

- **Entry gate — behavioural sandbox (`zee gate add … --behavioral`)** —
  Phase 2 of the entry gate. Opt-in, and the *only* path that executes an
  artifact: it detonates the artifact's install hook (`install.sh` /
  `setup.sh` / `pre`/`postinstall.sh`) inside an isolation backend and
  watches what it actually does at runtime, so it catches stealers that
  slip past the static scan (e.g. a credential path assembled at runtime).
  Signals become G8xx flags folded into the same LOW/MEDIUM/HIGH verdict:
  `G801` a seeded **decoy credential was read and exfiltrated**, `G802`
  an outbound network attempt, `G803` a write to a persistence / autostart
  location (shell rc, LaunchAgent, agent config), `G804` a decoy read
  (access-time, best-effort), `G805` the run was killed on timeout.
  - **The detonator is isolated from the Zee core (invariant I7)** — a
    separate subpackage (`zee.gate.sandbox`) the core never imports.
  - **Hard interlock (I2):** if no isolation backend is available the
    artifact is **never run on the bare host** — the run is skipped with a
    `G809` notice and the static verdict stands. MVP backend is macOS
    native `sandbox-exec` (zero install); Docker / Linux backends slot in
    behind the same interface later.
  - **Containment, honestly (I5/I6):** writes are confined to a throwaway
    sandbox HOME, all network is denied except one loopback port routed to
    a local FakeNet sink, and reads of the real user homes (`/Users`,
    `/private/var/root`) are denied so a hook cannot read the host's real
    `~/.ssh` / `~/.aws` / source and exfiltrate it. Only credential-shaped
    **decoys** (never real secrets) are planted as bait. This contains
    writes + network and blocks real-home reads; it is layered risk
    reduction, not complete detection — TLS bodies sent through a CONNECT
    tunnel are contained but opaque. Default behaviour is unchanged
    (without `--behavioral` nothing is ever executed). 15 new tests.

## [0.7.0] — 2026-06-23

### Added

- **Optional MCP layer (`zee[mcp]`)** — a separate, opt-in stdio server
  (`zee mcp`) that exposes Zee's signals over the Model Context Protocol
  for an agent such as Claude Code. Read-only + propose-only: resources
  (`zee://status`, `zee://events/recent`, `zee://containment/active`,
  `zee://policy`) and `query_*` tools never mutate; `propose_*` tools
  return a plan plus the command a human must run and never execute.
  Safe by default (`enabled=false`, `expose_actions=false`,
  `redact_paths=true`), never reaches the HMAC restore secret, and audits
  every access with `source=mcp` (free-text args and paths are redacted in
  the audit log too when `redact_paths=true`). Time filters compare real
  instants, not raw strings, so mixed timezone offsets agree with
  `zee status`. Core stays dependency-free; MCP is an optional extra
  (`mcp>=1.0,<2`). 22 new tests (102 → 124).
- **Entry gate (`zee gate`)** — pre-install inspection for AI artifacts
  (Claude Code skill / MCP server / package). `zee gate add <source>`
  fetches the artifact into a quarantine directory **without executing
  it**, statically inspects it (dynamic-exec, `curl|bash`,
  download-then-exec, encoded blobs, credential-path reads, magic-byte
  mismatch, prompt-injection text, escaping symlinks, and a
  GitHub-distributed denylist), assigns a LOW / MEDIUM / HIGH verdict
  with evidence, and promotes to the real install dir **only on LOW**
  (`--promote-to`). Exit code is the verdict (LOW=0, MEDIUM=1, HIGH=2)
  for CI / pre-install hooks. Phase 0 (contracts) + Phase 1 (static MVP,
  skill + MCP); the sandboxed behavioural run is a later phase. stdlib
  only — no execution of untrusted code, no network, core stays
  dependency-free. 16 new tests (124 → 140).

### Fixed

- **LP (`docs/index.html`) Red Team citation** — replaced the remaining
  `red.anthropic.com` top-page link with the same per-article URLs already
  used in README ja / en, so the public site no longer lags the READMEs.

## [0.6.0] — 2026-06-10

### Fixed

- **Watcher re-registration after decoy delete / rename** — macOS
  (kqueue) and Linux (inotify) now re-register the new vnode / inotify
  watch descriptor when a decoy is deleted or renamed and later
  re-created (e.g. after running `zee seed` again). Previously the
  watcher silently stopped detecting events on the restored file.
  Windows (`ReadDirectoryChangesW`) watches the parent directory and
  was not affected. Verified by a new integration test on macOS
  (`test_delete_and_reseed_fires_event`).

- **`zee status` now reports malformed JSON lines** — partial or
  corrupt lines in `events.jsonl` (e.g. written during a concurrent
  `zee watch`) are silently skipped as before, but the count of
  skipped lines is now surfaced as an in-band warning in the status
  output, consistent with the existing `read_error` design.

### Changed

- **Anthropic Red Team citation links in README ja/en** — replaced the
  general `red.anthropic.com` top-page link with specific article URLs:
  [Partnering with Mozilla to improve Firefox's security](https://red.anthropic.com/2026/firefox/)
  and [Claude Mythos Preview](https://red.anthropic.com/2026/mythos-preview/).
  The Glasswing link was already specific and is unchanged.

- **STARTER_GUIDE ja/en** — canary receiver setup is now a numbered
  step (step 3) in the dry-run walkthrough, with a Canarytokens.org
  quickstart. Previously it appeared only at the end of the section,
  making it easy to miss for macOS / Windows operators.

### Added

- **Automatic log rotation** — `events.jsonl` and `metrics.jsonl` are
  renamed to `<file>.YYYYMMDD_HHMMSS` when they exceed 10 MB. Rotated
  files are kept permanently (never auto-deleted; they are evidence).

- **`examples/integration_smoke.py`** — opt-in local script that
  reproduces the Discussion #3 walkthrough automatically: seed decoy,
  detect modification, verify delete → re-seed → re-detect cycle.
  Not part of CI; run manually with `python examples/integration_smoke.py`.

- **Burst detection boundary tests** — three new test cases: exactly
  300 s window boundary, mixed-timezone inputs, and event just inside
  the 30 d window.

### Fixed (post-review)

- **macOS watcher: `_kq is None` guard in `_try_reregister`** — if
  `stop()` races with the re-registration loop, `self._kq` can be
  `None` at the point `_try_reregister` calls `kq.control()`. Added an
  early-return guard to prevent `AttributeError`.

- **STARTER_GUIDE ja/en: canary URL example domain corrected** — the
  example `export ZEE_CANARY_BASE_URL="https://canarytokens.com/..."`
  used `.com` while the service is at `.org`; now consistently
  `canarytokens.org`.

- **Test: `test_burst_exactly_at_window_boundary` stability** — changed
  the "now" timestamp from `_ts(0, NOW)` to `_ts(1, NOW)` so
  `compute()`'s fresh `datetime.now()` cannot exclude the event on slow
  CI runners.

### Documentation

- **SECURITY.md** — added two new Honesty-boundaries entries:
  (1) `cut_egress` "local" definition (RFC 1918 + loopback; IPv4
  link-local and IPv6 ranges not covered); (2) log rotation behaviour
  and evidence-preservation policy. Clarified that rotation is
  triggered on next write ("auto-rotates on next write when it exceeds
  10 MB") to avoid implying a background daemon.

## [0.6.0] — 2026-06-09 (first part; the 2026-06-10 entry above continues this release)

### Added

- **`zee status` command** — read-only summary of trap activity
  and containment state. Reads `events.jsonl` and `cut_state.jsonl`
  directly; no `assets.toml` required.

  Output:
  - Event counts over 24 h / 7 d / 30 d, broken down by
    `read-class` and `change-class`
  - Per-asset 30 d counts with current cut state (clear /
    ⚠ ACTIVE — method / since)
  - Assets that have an active `zee cut` but no events in the log
    are shown in the per-asset section (e.g. a manual pre-emptive cut)
  - **Burst detection**: flags when ≥ 2 `change-class` events occur
    within a 300 s sliding window in the last 30 days

  Usage: `zee status`

### Internal

- 17 new tests for `status.py` (95 total)
- `StatusReport.read_error` surfaces an `OSError` on `events.jsonl`
  as an in-band warning rather than silent zero counts

---

## [0.5.0] — 2026-06-01

**Zee becomes a collective.** This release does not add any
detection or containment behaviour — it formalises the operating
model the project will use from here onward: a **seeded OSS** where
the maintainer publishes a reference implementation, and the people
who actually use Zee keep their forks alive in their environments.

The motto is **"defense by everyone, for everyone — みんなで防災"**.

### Why this release

Through v0.1–v0.4 the maintainer chased every OS shift personally.
That model does not scale (it's the classic OSS maintainer-burnout
trap) and it does not match Zee's own "this is a floor, not a
ceiling" stance. v0.5 makes the seeded-OSS model explicit so a
single operator's drift never becomes the project's drift.

### Added

- **`CONTRIBUTING.md` rewrite** introducing the "seeded OSS / 各自
  メンテ" model. Explains why PRs are welcome but not required, why
  the maintainer does not promise to chase OS updates forever, and
  what `docs/maintenance/` is for.
- **`docs/maintenance/` directory** with prompt templates for the
  common failure modes:
  - `mac_launchd_update.md` — Apple ships an `launchd` /
    `networksetup` / `pfctl` / `kqueue` change
  - `linux_systemd_update.md` — `nmcli` / `nft` / `iptables` /
    `inotify` shifts or distro switch
  - `windows_service_update.md` — `Get-NetAdapter` / `netsh` /
    locale / Service registration shifts
  - `python_version_bump.md` — new Python release deprecates
    something Zee depends on
  Each template hands the AI tool (Claude / Cursor / Copilot /
  Codex) enough context to produce a working patch as a diff. The
  recommended flow ends with "post your fix to Discussions".
- **GitHub issue / PR templates** (`.github/ISSUE_TEMPLATE/` and
  `.github/PULL_REQUEST_TEMPLATE.md`) that route environment-specific
  problems toward GitHub Discussions instead of the Issue tracker,
  and explicitly position upstream merge as one outcome among
  several (the others being "post your write-up to Discussions",
  "edit the Wiki", "just keep your fork").
- **README ja/en "みんなで防災" section** at the top of the user-
  facing prose.
- **LP (`docs/index.html`) collective block** between Limitations and
  Get-it, with four cards (Maintenance Q&A / Show your fork / Wiki /
  docs/maintenance).
- **`SECURITY.md` "Shared vs. private logs" table** — clarifies
  exactly which Zee artefacts are safe to share in Discussions /
  Wiki and which are private to the operator. `events.jsonl`,
  `canary_tokens.jsonl`, `cut_state.jsonl`, `restore_token` stay
  private. Source code and maintenance write-ups are shared freely.
- **CLI hint on ZeeError** — when `zee` exits with an error the
  next line nudges the operator toward
  https://github.com/KAMANOI/zee/discussions/categories/q-a
  so they can search for / share their fix.

### Operator action needed (once)

The maintainer needs to enable GitHub Discussions and the Wiki on
the repository for the URLs above to resolve. Until that switch is
flipped, the links resolve to a "this is disabled" page; no code
breakage, just a flat experience for arriving readers. This is a
two-click toggle in the repo Settings.

### Changed

- **CLI stderr on `ZeeError`** — `zee` now appends a two-line hint
  pointing at `Discussions / Maintenance Q&A` after most error
  prints. The exit code and the primary error message are unchanged,
  but `stderr` carries the extra hint. Plain user-input errors
  (`Z102` unknown asset, `Z602`/`Z603`/`Z604` restore-token problems)
  suppress the hint so the operator is not pointed at a community
  board for a typo.

### Not changed

- No detection / containment / restore behaviour changed. No
  on-disk file layouts (`events.jsonl`, `cut_state.jsonl`,
  `canary_tokens.jsonl`, `restore_token`) changed. v0.4.1 state is
  forward-compatible.
- All 78 unit tests still pass on Linux / macOS / Windows × Python
  3.11 / 3.12 / 3.13 in the CI matrix.

## [0.4.1] — 2026-05-31

The v0.4.0 CI matrix surfaced two Windows-specific issues that were
invisible while only the maintainer's macOS shell ran the suite.
Both fall out of NTFS using ACLs rather than POSIX bits and out of
Windows using ``\\`` as the path separator. None of v0.3's
documented invariants change; the fix is to skip the POSIX-only
behaviour on win32 and update the tests to match.

### Fixed
- ``recovery/auth.load_token``: skips the POSIX group/world-read
  refusal on win32 (NTFS ACLs cover the same threat there; the
  fall-through still reads the token). The check is unchanged on
  Linux / macOS.
- ``policy/allowlist._is_path_secure``: skips the POSIX
  group/world-write refusal on win32 for the same reason; the
  loader still rejects unreadable / missing files on every OS.
- ``test_canary_token`` / ``test_cut_state`` / ``test_restore_auth``
  / ``test_allowlist``: owner-only-mode assertions are guarded by
  ``pytest.mark.skipif(sys.platform == "win32")``. The path-
  normalisation test now uses ``tmp_path`` so it exercises real
  absolute paths on every OS (the previous hard-coded ``/tmp/...``
  fed Windows a string the loader normalised to ``\tmp\...``).

### Documentation
- ``SECURITY.md`` "Honesty boundaries" entry on the restore_token
  now states that on Windows the POSIX bit check is skipped and the
  effective protection is the per-user NTFS ACL on ``%USERPROFILE%
  \\.zee``.

## [0.4.0] — 2026-05-31

The 78-test suite from v0.3 now runs on every push across the full
support matrix. The v0.3 "Windows hardware is not yet tested by the
maintainer" entry in `SECURITY.md` is replaced with the CI link.

### Added
- **GitHub Actions test matrix**
  (`.github/workflows/test.yml`): Ubuntu / macOS / Windows ×
  Python 3.11 / 3.12 / 3.13 = 9 jobs, plus a dedicated
  `canary-configured` job that runs the suite under
  `ZEE_CANARY_BASE_URL`. Each job runs `pytest`, then smoke-tests
  the CLI (`zee --version`, `zee capability`,
  `zee init-restore-token`). Action versions are pinned by SHA.
- **Dependabot** (`.github/dependabot.yml`): weekly bumps for the
  pinned GitHub Actions SHAs.
- **README CI badge** (ja / en): live build status link to the
  Actions runs.
- **`examples/seed_demo_decoys.py`**: one-shot script that drops
  three example decoys under `~/Documents/zee-decoys/`, prints the
  paste-able `[[assets]]` stanza, and optionally takes
  `--canary-base-url` to exercise the v0.2 canary path locally.
- **`examples/Dockerfile.linux-smoke`**: minimal Python 3.13 image
  that runs `pytest` and the CLI smoke under a non-root user. Stands
  in for a maintainer Linux machine when verifying a release.
- **`tests/__init__.py`**: empty file so IDE indexers and `pytest`
  plug-ins that walk `__init__.py` chains discover the test package
  without surprises.
- **pyproject.toml `[project.urls]`**: Issues / Changelog /
  Documentation / Sponsor / Security Advisories entries.

### Changed
- `SECURITY.md`'s "Honesty boundaries" entry on Windows hardware now
  points to the CI matrix instead of saying "untested".

### Tests
- 78 unit tests passing (same suite as v0.3.0), now exercised across
  the full OS / Python matrix on every push.

## [0.3.0] — 2026-05-31

Closes every "Known limitation" listed in v0.2's `SECURITY.md`. The
"Known limitations (current release)" section is now empty and has
been removed.

### Added
- **`zee init-restore-token`** (spec L3). Generates a 256-bit
  restore_token at `~/.zee/restore_token` (0600, parent 0700) and
  prints it once. `zee restore` now requires `--token <TOKEN>` or
  `ZEE_RESTORE_TOKEN=<TOKEN>`. Standard library only; constant-time
  comparison via `hmac.compare_digest`. A `restore_token` file with
  loose permissions (group/world read or write) is refused at load
  time. Stops a casual same-user attacker from reverting containment
  from a second shell session; root-equivalent attackers still
  bypass it (the README recommends wrapping `zee restore` in `sudo`
  or running Zee under a dedicated user for multi-user deployments).
- **Cut-state log** (`src/zee/telemetry/cut_state.py`, spec L2).
  Each cut writes a `cut` record to
  `~/.local/state/zee/cut_state.jsonl` (0600 / parent 0700) listing
  the specific interfaces, services, or firewall-rule names Zee
  modified. `zee restore` reads the latest unresolved record and
  reverses only those changes; the v0.2 "enable everything" side
  effect (re-enabling interfaces that another tool had disabled at
  the same time) is gone. Missing or absent records fall back to
  the v0.2 behaviour with a stderr warning.
- **PowerShell `Get-NetAdapter`** for Windows interface enumeration
  (spec L1). Locale-independent — works on Japanese / German /
  French / etc. Windows where the legacy `netsh interface show
  interface` parser returned zero results. The netsh parser is
  retained as a fallback for environments where PowerShell is
  unavailable.
- **Error codes**: `Z602` (restore token required), `Z603` (restore
  token not initialised), `Z604` (restore token invalid).
- New tests: `test_cut_state.py` (7 cases), `test_restore_auth.py`
  (9 cases), `test_windows_iface_enumeration.py` (4 cases). Total
  test suite: 78 (was 56 on v0.2.0).

### Changed
- **`events.jsonl` schema** (spec L4): `decoy_path` is no longer
  persisted. Each `trap_event` record carries `decoy_ref` of the
  form `"<asset_id>#<index>"` (0-based index into the asset's
  `decoy_paths`). A root attacker reading the log alone can no
  longer enumerate every decoy's filesystem location; correlation
  back to the full path goes via `assets.toml`. This is a
  log-format breaking change for downstream analysis tools.
- **`cut_full()` / `cut_egress()` signatures** gain optional
  `asset_id=` and `cut_state=` keyword args. The `tuple[bool, str]`
  return type is unchanged. Internal stubs and the responder pass
  both so the cut-state record is written.
- **`restore()`** reads the cut-state log and undoes only the
  specific changes Zee recorded.

### Tests
- 78 unit tests passing (`pytest tests/`).

### Migration notes
- Existing `events.jsonl` files written by v0.1 / v0.2 still contain
  `decoy_path`. New entries from v0.3 onwards use `decoy_ref`.
  Downstream parsers must accept both keys for the transition window.
- Operators upgrading from v0.2 must run `zee init-restore-token`
  once before they can call `zee restore` again. The token file
  lives at `~/.zee/restore_token`.

## [0.2.0] — 2026-05-31

Canary URL wiring: macOS / Windows read detection moves from "planned"
to working. The v0.1 honesty disclosure ("read-only attacker activity
against a macOS / Windows decoy is not observed") is lifted when
operators configure a receiving endpoint.

### Added
- **Canary URL embedding in the seeder.** When the operator sets
  ``ZEE_CANARY_BASE_URL`` to an external receiver they control
  (Canarytokens.org, a self-hosted webhook, an AWS Lambda, …), the
  env / credentials / notes templates now carry a canary URL line of
  the form ``{base_url}/{token_id}``. ssh_key templates are left
  alone (the OpenSSH armor format does not survive a foreign URL).
  Embedded lines contain no Zee-origin words (``canary`` / ``zee`` /
  ``tripwire`` / ``decoy``); the entire rendered decoy is now
  free of those markers (enforced by ``tests/test_seeder_canary.py``).
- **Persistent ``CanaryTokenRegistry``.** Issued tokens append to
  ``~/.local/state/zee/canary_tokens.jsonl`` (parent dir 0700, file
  0600), so restarting ``zee watch`` with the same ``base_url``
  rebinds the same URL to each decoy_path (idempotent across runs).
  Records whose ``base_url`` differs from the current configuration
  are skipped on load.
- ``zee capability`` and the per-OS ``Capability`` reflect whether
  ``ZEE_CANARY_BASE_URL`` is configured (``uses_canary_fallback``).
- Operator-facing receiver guidance in README, ARCHITECTURE,
  STARTER_GUIDE, business_guide, and ``assets.example.toml``.

### Changed
- Decoy template body strings no longer contain ``zee`` or ``decoy``;
  attackers cannot ``grep`` for those words to identify decoys.
- ``CanaryTokenRegistry.issue`` / ``issue_for_decoy`` now raise
  ``RuntimeError`` when ``base_url`` is unset. The ``about:zee/c/…``
  fallback was removed — emitting a clearly Zee-origin URL into a
  decoy made the deception trivially detectable.
- ``CanaryTokenRegistry`` ``base_url`` validation accepts
  case-insensitive ``https://`` and strips whitespace before checking.
- Canary URL shape is ``{base_url}/{token_id}`` (no ``/c/`` prefix);
  the operator's chosen path structure is what an attacker sees.

### Tests
- 56 unit tests passing (``pytest tests/``). Added
  ``test_seeder_canary.py`` (8 cases) and expanded
  ``test_canary_token.py`` (9 cases: persistence, idempotency,
  base_url switching, owner-only file mode).

### Migration notes
- Existing decoy files from v0.1 deployments are not rewritten on
  upgrade (the evidence-preservation rule). To embed canary URLs in
  files that pre-date v0.2, delete the existing decoy file under your
  Zee-managed directory and let ``zee watch`` re-seed it.

## [0.1.0] — 2026-05-30

First public release.

### Added
- **MVP implementation** (`src/zee/`): decoy tripwire with automated
  containment. Standard library only (TOML config via `tomllib`; no
  third-party runtime dependency).
- **Watcher backends**:
  - Linux: `inotify` via ctypes (open / read / modify, plus
    delete-self / move-self for decoy disappearance).
  - macOS: `kqueue/EVFILT_VNODE` (change events) + canary URL fallback
    for read signals.
  - Windows: `ReadDirectoryChangesW` via ctypes (change events) +
    canary URL fallback (untested on Windows hardware).
- **Responder**: fixed notify → fire-and-forget webhook → mode resolve
  → `confidence=high` only contain. `dry_run` is the default.
- **Cut backends** (per-OS): `full` (interface disable) and `egress`
  (block outbound to non-local destinations). Both require admin
  privilege and never run on `dry_run`.
- **Policy**: asset profile TOML (`assets.toml`) with
  `response_mode` × `cut_method` resolution. Allowlist data structure
  for legitimate processes (responder wiring is a follow-up phase).
- **Recovery**: manual `zee restore <asset_id>` — no auto-reconnect.
- **Telemetry**: JSON Lines event log, latency metrics, false-positive
  markers, capability matrix.
- **Documentation**: README / ARCHITECTURE / STARTER_GUIDE / RESEARCH
  in Japanese and English.
- **OSS governance**: LICENSE (MIT), SECURITY.md, CONTRIBUTING.md,
  CODE_OF_CONDUCT.md.

### Design choices that are intentionally not features
- No automatic reconnection after a cut. Recovery is always manual.
- No "defense rate" numbers. Effectiveness is not independently
  validated and we will not publish a percentage that isn't measured.
- No applicant-restricted / gated distribution. Everything is MIT.
- No promise that Zee stops any named attacker class.

### Tests
- 33 unit tests passing (`pytest tests/`). Covers confidence gate,
  dry_run, mode resolution, async webhook non-blocking, duplicate-decoy
  detection, macOS kqueue change events.

### Known limitations
- Linux backend: code complete; continuous-run verification on Linux
  hardware not yet done.
- Windows backend: code complete; not yet verified on Windows hardware.
- macOS: verified on developer hardware.
