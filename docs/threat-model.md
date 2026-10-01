# Zee entry gate and distribution threat model

## Scope

Zee has two security surfaces: an exit-side system of decoy tripwires and
containment responses, and the entry-side `zee gate` inspection workflow. This
document models threats to the entry gate and to Zee's own distribution, plus
the evidence store and the containment-report export (last section).

The exit-side boundaries are documented in [README Limitations](../README.md#limitations--zee-がやらないこと),
[SECURITY Honesty boundaries](../SECURITY.md#honesty-boundaries-current-release),
and [gate Limits](gate.md#limits-invariant-i5); they are not repeated here.

## Attacker positions (entry gate)

- **Malicious from the start.** An artifact author includes harmful content in
  the first version. Zee applies its native static checks (`G1xx`–`G7xx`).
- **Replaced at a registry.** A previously legitimate package is replaced or a
  malicious release is served through its distribution registry. Zee applies
  imported scanner findings as `G901` when reports are supplied with
  `--import-scan`.
- **Changed after adoption (Rug Pull).** An artifact changes after it was
  reviewed or promoted. `zee gate audit` compares it with the recorded pin;
  users should also pin the artifact they install.
- **Inspection-aware evasion.** An artifact uses obfuscation, conditional
  branches, or environment checks to conceal behavior during inspection. The
  opt-in `--behavioral` mechanism can exercise an install hook when a supported
  isolation backend is available, but its effectiveness against such behavior
  has not been measured.

## Detection limits by mechanism

| Mechanism | Current reach and limit |
| --- | --- |
| Static inspection | Matches implemented patterns. It can miss obfuscation, runtime-generated content, and reworded natural-language instructions. |
| Denylist | Matches known hashes or names only. Per-entry signing is future work; see the [threat-list integrity notes](threat-list.md#integrity). |
| Behavioural sandbox | Available only through macOS `sandbox-exec`. Linux and Windows do not execute the artifact, so behavioural inspection cannot be performed there. TLS bodies carried through a CONNECT tunnel are opaque. An artifact that detects the sandbox can behave harmlessly inside it. |
| Audit | Runs only when requested. It checks pinned artifacts for drift and is not live, real-time monitoring of running processes. |

## Sandbox backend matrix

The implemented backend registry is `_BACKENDS` in
[`src/zee/gate/sandbox/backends.py`](../src/zee/gate/sandbox/backends.py). It
contains only `MacosSandboxExec`; when no registered backend is available, Zee
skips execution.

| Operating system | Backend | Behavioural execution |
| --- | --- | --- |
| macOS | `sandbox-exec` | Yes, when the executable is available |
| Linux | None; Docker and bubblewrap are not implemented | No |
| Windows | None | No |

## Complementary scanners (Snyk / Socket)

Zee's entry gate (`G1xx`–`G9xx`) targets AI-artifact-specific threats:
instructions aimed at an AI agent (prompt injection in Claude skills or MCP
artifacts), excessive permission requests, and post-adoption drift (Rug
Pull). It does not maintain a database of known CVEs, and its denylist only
matches hashes or names it has already been told about (see Detection
limits above). Snyk and Socket cover different, complementary ground:

- **Snyk.** `snyk code test` can emit SARIF (`--sarif` /
  `--sarif-file-output`), which `zee gate add --import-scan` consumes as
  `G901` findings ([Snyk docs](https://docs.snyk.io/developer-tools/snyk-cli/commands/code-test)).
  Snyk's SCA products separately track known CVEs against dependency
  manifests; Zee does not.
- **Socket.** Its documented checks are behavioral supply-chain signals
  (install scripts, typosquats, known malware, native code, telemetry),
  delivered through a GitHub App or CLI, not a CVE database
  ([Socket for GitHub](https://docs.socket.dev/docs/socket-for-github),
  [Socket introduction](https://docs.socket.dev/docs/introduction)). Neither
  page documents SARIF output, so Zee cannot confirm today whether Socket
  findings can reach `--import-scan`.

Known-CVE tracking, behavioral supply-chain analysis, and AI-artifact
inspection are three separate mechanisms; none substitutes for the others.
See [gate.md](gate.md#using-zee-with-snyk--socket--semgrep) for the
command-level combination steps and the current verified/unverified status
of each integration.

## Out of scope (current release)

- Live, real-time network monitoring and immediate interruption of running
  processes.
- Remote fetch from a URL, git repository, or package registry. `gate add`
  accepts a local path, so the user must obtain the artifact first.
- A signed threat list.
- Attribution of an observed event to a specific process.

## Zee's own supply chain

As measured on 2026-09-05, this Zee project is not published on PyPI, npm, or
Homebrew. Packages named `zee` in those registries are unrelated works from
other authors. Install Zee from this repository and pin a tag or full commit
SHA; see the [README installation instructions](../README.md#インストール).
In CI, pin the Action as `uses: KAMANOI/zee@<tag|sha>`.

## Evidence store and containment export

Covers `events.jsonl` / `metrics.jsonl` (including rotated
`*.YYYYMMDD_HHMMSS` segments), `zee export`, and the MCP tool
`query_containment_report`.

| Threat | What Zee does | Limit |
| --- | --- | --- |
| A local attacker edits, deletes or reorders a log line | Each record carries `prev_hash` / `record_hash` (SHA-256 chain, starting at a fixed genesis value). `zee export` verifies all segments in order and reports `corrupted`, `chain_break`, `head_missing`, `legacy_after_chain`. | The hash is **unkeyed**. Zee assumes the attacker is on the host (ARCHITECTURE.md), and an attacker who can write the log can recompute every hash. Detection holds only against edits that do not recompute the chain. |
| Records removed from the end of the log | — | **Not detected.** A truncated chain is still a valid chain. Nothing is anchored outside the host. |
| Older rotated segments moved away | Reported as `head_missing`. | Cannot tell an operator's clean-up from an attacker's. |
| A corrupted or unreadable log blocks containment | Every append is wrapped: failures are logged and swallowed, so `responder.sequence.handle()` still notifies and cuts. Concurrent appends (threads and processes) are serialised with a lock; only the last 64 KiB is read per append. | A failed append loses that evidence record (it is logged to the Zee logger only). |
| Export output overwrites or leaks a file | Output is written to `O_EXCL` + `O_NOFOLLOW` temp files at 0600 and moved into place only after both are complete; an existing file or symlink at the target stops the export (Z701) unless `--force`, which replaces the link itself, never its target. | A failed run can leave a 0600 temp file next to the target (named in the error). |
| Recipient trusts the export as proof | `chain_verification` states what was checked; `export_sha256` covers the export itself. | The export carries no per-line hashes, so the recipient cannot re-verify the chain; they rely on Zee's local result. `export_sha256` shows only that the export was not changed after it was produced (if a copy was kept elsewhere). |
| Sensitive data in the export | `detail` (may contain paths) is masked unless `--no-redact`. MCP follows the server's redaction setting and returns at most `limit` events (default 50). | `asset_id` is not masked. Operators must not put personal or customer names in asset ids. |
| MCP read path changes local state | The report path is read-only; reading containment state no longer creates or chmods the state directory. Only the MCP audit line is written. | — |

Zee never sends the export anywhere and has no code that connects to or acts
on an attacker's machine.

## What this document is not

Zee's effectiveness has not been measured, and it has not been independently
validated. Verify its behavior in your own environment before production use.

### 日本語要約

Zee には出口側の囮と入口側の `zee gate` があり、本書は入口と配布を対象にします。
静的検査、外部結果の取込、ピン監査、任意の動的検査を組み合わせます。
静的検査と既知リストには、難読化や未知の内容を見逃す限界があります。
動的検査は macOS の `sandbox-exec` でのみ実行され、Linux / Windows では実行されません。
ライブ通信監視、即時遮断、リモート取得、署名付き脅威リスト、プロセス特定は対象外です。
Zee は PyPI・npm・Homebrew では配布されておらず、同名パッケージは無関係です。
導入時はタグまたは commit SHA、CI では `KAMANOI/zee@<tag|sha>` に固定します。
証跡ログは鍵なしのハッシュチェーンで、途中の書き換え・削除と先頭の欠落は検知しますが、末尾の切り詰めとホスト上の攻撃者による全ハッシュの再計算は検知できません。`zee export` は 0600・既存ファイルやリンクを上書きしない形で書き出し、何も送信しません。証跡の書き込み失敗は通知・遮断を止めません。
Zee は既知 CVE のデータベースを持たず、AI アーティファクト固有の脅威（指示のすり込み・過剰な権限要求・Rug Pull）だけを見ます。
既知脆弱性は Snyk、振る舞いベースのサプライチェーン検知は Socket と役割が異なり、併用が前提です（詳細は gate.md）。
効果は未測定で、独立検証もありません。本番前に利用環境で確認してください。
