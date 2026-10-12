# Zee の機能 ↔ OWASP Top 10:2025 / MITRE ATT&CK 対応表

評価者・当局・企業が使う共通言語で Zee の機能を説明するための対応表。英語版：[owasp-attack-mapping.en.md](./owasp-attack-mapping.en.md)

## 確認した版と日付

| 対象 | 版 | 確認日 | 確認した一次情報 |
|---|---|---|---|
| OWASP Top 10:2025 | 2025 版（A01〜A10） | 2026-10-12 | https://top10.owasp.org/2025/ の A01・A02・A03・A05・A06・A08・A09・A10 の各ページ |
| MITRE ATT&CK（Enterprise） | v19.2（サイトの現行版表示：2026-04-28 公開の v19。技法の名称・定義は公式 STIX データ `enterprise-attack-19.2.json`〔更新 2026-08-05〕で確認） | 2026-10-12 | https://attack.mitre.org/techniques/ の各技法ページ。バージョン一覧：https://attack.mitre.org/resources/versions/ |
| Zee | `main` abd956f（最新タグ v0.12.0 ＋ 未リリースの変更） | 2026-10-12 | 本リポジトリのソース |

## 読み方

- **表1（実装済み）**は、`main` に入っていて `zee` コマンド（`gate` / `watch` / `export` / `incident-report`）から実際に呼ばれる機能だけを載せる。**表2（設計中・未実装）**は別表で、表1と混ぜない。
- **OWASP 欄**は、その機能が対処する OWASP 2025 の項目。**ATT&CK 欄**は、その機能が検査・観測する対象が、当該技法の実行過程で現れる挙動であることを示す。Zee が識別するのは「囮に触れた種類（読み取り／変更）」や「成果物に含まれるパターン」であり、技法そのもの（たとえば暗号化か破壊か）の判別ではない。技法 ID はその挙動を共通言語で呼ぶための索引として使う。
- **根拠のコード**は `ファイル:関数` 形式。**側の記述**は、各一次情報の該当箇所の要旨（短い引用）。
- 囮への接触のうち、**変更系（書き込み・削除・名前変更）だけが自動封じ込めの対象**になる。**読み取りは通知にとどめ、遮断するかは人が判断する**（`zee cut`）。自動遮断は、資産プロファイルで `response_mode: auto` を明示し `dry_run: false` にした資産だけで動く。
- Zee は攻撃元の機器への接続・操作をしない。出口側の機能は検知・通知・自端末の遮断・証跡の書き出しまでで、その先は警察・PPC などの窓口に人がつなぐ（[containment-report-mapping.md](./containment-report-mapping.md)）。
- 効果は未測定（README 冒頭の Project Status のとおり）。本表は「どの共通言語でどの機能を説明できるか」を示すもので、検知率や防御率を示すものではない。

## 表1　実装済みの機能

### A. 入口ゲート（`zee gate`）— OWASP A03 に対応

OWASP [A03:2025 Software Supply Chain Failures](https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/) は、「信頼できない出典の部品が本番環境で使われる、または本番に影響する」状態と、サプライチェーン上の変更を追跡していない状態を脆弱性として挙げる（原文：“components from untrusted sources … are used in or can impact on production environments”／“you do not have a change management process or tracking of changes within your supply chain”）。入口ゲートは、AI スキル・MCP・npm・PyPI・VS Code 拡張を**導入する前に**、実行せずに検査する。

| # | Zee の機能 | 根拠のコード | OWASP 2025 | ATT&CK v19.2 | 一次情報の該当記述（要旨） |
|---|---|---|---|---|---|
| E1 | 導入前の隔離コピーと静的検査・判定（実行しない） | `gate/inspector.py:inspect_source`、`gate/fetch.py:fetch_local` | [A03](https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/) | [T1195 Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/) | A03：信頼できない出典の部品が本番に影響する。T1195：“manipulate products or product delivery mechanisms prior to receipt by a final consumer” |
| E2 | G101：インストール／ポストインストールのフックを申告している成果物を検出 | `gate/inspector.py:_install_hook_flags` | [A03](https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/)（Scenario #3） | [T1195.001 Compromise Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1195/001/) | A03 Scenario #3：2025 年の npm ワーム Shai-Hulud はポストインストールスクリプトで情報を窃取・送出した。T1195.001：pip・NPM パッケージが悪意あるコードの混入先になりうる |
| E3 | G201／G202：動的コード実行（eval／exec／Function）、サブプロセス・シェル起動を検出 | `gate/static_checks.py:_PATTERNS`（G201・G202） | [A03](https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/) | [T1059 Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) | T1059：“abuse command and script interpreters to execute commands, scripts, or binaries” |
| E4 | G203：ダウンロードをそのままシェルへ渡す記述（`curl … \| bash` 型）を検出 | `gate/static_checks.py:_g203_start`、`_G203` | [A03](https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/) | [T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)、[T1059.004 Unix Shell](https://attack.mitre.org/techniques/T1059/004/) | T1105：外部のシステムから侵害環境へツールやファイルを転送する。T1059.004：Unix シェルのコマンドとスクリプトの悪用 |
| E5 | G204：エンコードされたペイロードを復号して実行する記述を検出 | `gate/static_checks.py:_g204_start`、`_G204` | [A03](https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/) | [T1027 Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/) | T1027：ファイルの内容を “encrypting, encoding, or otherwise obfuscating” して発見・解析を難しくする |
| E6 | G301／G302：長い base64／16 進のかたまり（詰め込まれたペイロードの可能性）を検出 | `gate/static_checks.py:_PATTERNS`（G301・G302） | [A03](https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/) | [T1027](https://attack.mitre.org/techniques/T1027/) | 同上 |
| E7 | G401：テキスト拡張子なのに実行ファイルの先頭バイト（マジックバイト）を持つファイルを検出 | `gate/static_checks.py:_magic_flag` | [A03](https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/) | [T1036.008 Masquerade File Type](https://attack.mitre.org/techniques/T1036/008/) | T1036.008：悪意あるペイロードを、“file's signature, extension, icon, and contents” の変更で正規のファイルに見せかける |
| E8 | G601：認証情報の保管場所（`.ssh`・`.aws`・`.npmrc`・`.env`・Keychain・Cookies など）を読む記述を検出 | `gate/static_checks.py:_PATTERNS`（G601） | [A03](https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/) | [T1552.001 Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)、[T1552.004 Private Keys](https://attack.mitre.org/techniques/T1552/004/)、[T1555.001 Keychain](https://attack.mitre.org/techniques/T1555/001/) | T1552.001：安全でない形で保存された認証情報を含むファイルを探す。T1552.004：秘密鍵・証明書ファイルを探す。T1555.001：macOS の Keychain から認証情報を取得する |
| E9 | G6xx：既知の悪意ある成果物のハッシュ・名前・ドメインとの照合（リポジトリ同梱の拒否リスト＋ローカルで育つ拒否リスト） | `gate/denylist.py:check` | [A03](https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/) | — | A03：信頼できない出典の部品を本番に入れない |
| E10 | G901：Semgrep JSON／SARIF 2.1.0 の検査結果を取り込み、同じ判定に合算（`--import-scan`） | `gate/imports.py:import_scan_file`、`import_scans` | [A03](https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/) | — | A03：脆弱性スキャンを定期的に行い、結果を追跡する |
| E11 | 導入した成果物の内容ハッシュを記録（ピン）し、後からの書き換え（Rug Pull）を `zee gate audit` で検出。ずれた版のハッシュはローカルの拒否リストに加わる | `gate/pins.py:PinRegistry.pin`、`gate/audit.py:audit_pins`、`cli.py:_cmd_gate_audit` | [A03](https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/)、[A08](https://top10.owasp.org/2025/A08_2025-Software_or_Data_Integrity_Failures/) | [T1195.002 Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/) | A03：サプライチェーン上の変更を追跡する。A08：ソフトウェアが期待した出典のもので、変更されていないことを検証する（署名ではなくハッシュ照合で行う）。T1195.002：ソフトウェアの “update/distribution mechanism” の改変などによる侵害 |
| E12 | 任意の動的検査（`--behavioral`）：インストールフックを隔離環境で動かし、囮の認証情報の読み取りと送出（G801）・囮の認証情報ファイルの読み取り（G804）を検出 | `gate/sandbox/runner.py`（G801・G804 の判定部）、`gate/sandbox/decoys.py` | [A03](https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/) | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | T1552.001：認証情報を含むファイルを探す |
| E13 | 同・永続化先への書き込み（G803：シェル rc、LaunchAgents、`.config/autostart`）を検出 | `gate/sandbox/runner.py`（G803 の判定部、`_PERSISTENCE_PATHS`） | [A03](https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/) | [T1546.004 Unix Shell Configuration Modification](https://attack.mitre.org/techniques/T1546/004/)、[T1543.001 Launch Agent](https://attack.mitre.org/techniques/T1543/001/)、[T1547 Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/) | T1546.004：ユーザーのシェル設定スクリプト経由の永続化。T1543.001：launch agent の作成・変更による永続化。T1547：起動・ログオン時の自動実行の設定 |

使い方の情報：入口ゲートは静的検査が中心で、既知 CVE のデータベースは持たない（脆弱性の追跡は Snyk 等と併用する。[gate.md](./gate.md)）。動的検査（E12・E13）は macOS の `sandbox-exec` でのみ実行され、Linux と Windows では実行しない（[threat-model.md](./threat-model.md)）。

### B. 出口側（囮・検知・通知・封じ込め・証跡）— OWASP A09 に対応

OWASP [A09:2025 Security Logging and Alerting Failures](https://top10.owasp.org/2025/A09_2025-Security_Logging_and_Alerting_Failures/) は、予防策に “Add ‘honeytokens’ as traps for attackers … any access generates logging data that can be alerted with nearly no false positives”（囮を置き、触れた時点で誤検知をほぼ出さずに警報にする）と “Ensure all transactions have an audit trail with integrity controls to prevent tampering or deletion”（改ざん・削除を防ぐ完全性管理つきの監査証跡）を挙げる。Zee の出口側はこの二つに直接対応する。

| # | Zee の機能 | 根拠のコード | OWASP 2025 | ATT&CK v19.2 | 一次情報の該当記述（要旨） |
|---|---|---|---|---|---|
| R1 | 囮ファイルの設置（認証情報ファイル・`.env`・秘密鍵形式・メモ）。通常業務では触られない囮への接触を高信頼イベントにする | `decoy/seeder.py:seed`、`seed_all`、`events.py:TrapEvent`（`decoy_touch` は `confidence="high"` 必須） | [A09](https://top10.owasp.org/2025/A09_2025-Security_Logging_and_Alerting_Failures/) | [T1552.001](https://attack.mitre.org/techniques/T1552/001/)、[T1552.004](https://attack.mitre.org/techniques/T1552/004/) | A09：honeytoken は通常業務で使われないため、触れた記録をほぼ誤検知なしで警報にできる。T1552.001・T1552.004：攻撃者が探す認証情報ファイル・秘密鍵ファイル |
| R2 | 囮への**書き込み・拡張**（変更系）を検知。3 OS 共通 | `watcher/backend_linux.py:_classify_mask`（IN_MODIFY）、`watcher/backend_macos.py:_classify_fflags`（WRITE・EXTEND）、`watcher/backend_windows.py:WindowsWatcher._loop` | [A09](https://top10.owasp.org/2025/A09_2025-Security_Logging_and_Alerting_Failures/) | [T1486 Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)、[T1565.001 Stored Data Manipulation](https://attack.mitre.org/techniques/T1565/001/) | T1486：ファイルを暗号化して可用性を奪う（検知分析 AN0603 に “overwrite of existing data”）。T1565.001：保存データの挿入・削除・改変 |
| R3 | 囮の**削除**（変更系）を検知。3 OS 共通 | `watcher/backend_linux.py:_classify_mask`（IN_DELETE_SELF）、`watcher/backend_macos.py:_classify_fflags`（DELETE）、`watcher/backend_windows.py:WindowsWatcher._loop` | [A09](https://top10.owasp.org/2025/A09_2025-Security_Logging_and_Alerting_Failures/) | [T1485 Data Destruction](https://attack.mitre.org/techniques/T1485/)、[T1486](https://attack.mitre.org/techniques/T1486/) | T1485：データとファイルを破壊して可用性を奪う。T1486 の手口の例：暗号化した新しいファイルを作って元のファイルを削除する（Apostle） |
| R4 | 囮の**名前変更**（変更系）を検知。3 OS 共通 | `watcher/backend_linux.py:_classify_mask`（IN_MOVE_SELF）、`watcher/backend_macos.py:_classify_fflags`（RENAME）、`watcher/backend_windows.py:WindowsWatcher._loop` | [A09](https://top10.owasp.org/2025/A09_2025-Security_Logging_and_Alerting_Failures/) | [T1486](https://attack.mitre.org/techniques/T1486/) | T1486：ランサムウェアでは対象ファイルが「暗号化され、しばしば名前も変更される」（説明文）。手口の例：BitPaymer は暗号化したファイルの名前に `.locked` を付ける |
| R5 | 囮の**読み取り・オープン**を検知（Linux：inotify）。読み取り系なので**通知のみ**で、遮断は人が判断する | `watcher/backend_linux.py:LinuxInotifyWatcher._loop`、`_classify_mask`（読み取り系）、`responder/sequence.py:handle`（読み取り系は遮断に進まない） | [A09](https://top10.owasp.org/2025/A09_2025-Security_Logging_and_Alerting_Failures/) | [T1552.001](https://attack.mitre.org/techniques/T1552/001/)、[T1552.004](https://attack.mitre.org/techniques/T1552/004/)、[T1005 Data from Local System](https://attack.mitre.org/techniques/T1005/) | T1552.001 の検知戦略 DET0307：安全でない認証情報ファイルへのアクセスを検知する。T1005：ローカルのファイルシステムから目的のファイルを探して集める |
| R6 | 囮に埋め込んだ canary URL が辿られたことを、運用者が用意した外部受信器で検知（macOS・Windows での読み取り検知。`ZEE_CANARY_BASE_URL` 設定時） | `decoy/canary_token.py:CanaryTokenRegistry.issue_for_decoy`、`decoy/seeder.py:_embed_canary` | [A09](https://top10.owasp.org/2025/A09_2025-Security_Logging_and_Alerting_Failures/) | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | A09：honeytoken への接触を警報にする。T1552.001：認証情報を含むファイルの探索と利用 |
| R7 | 検知時の通知：端末への通知（先に実行）→ webhook（任意・送りっぱなし）。通知は接触の種類（読み取り／変更）に応じた確認の手がかりと影響度の段階表示を含む | `responder/sequence.py:handle`、`notifier/local.py:notify_local`、`notifier/webhook.py:post`、`notifier/tier.py:classify` | [A09](https://top10.owasp.org/2025/A09_2025-Security_Logging_and_Alerting_Failures/) | — | A09：能動的な攻撃を検知して警報を出す。重要な警報とそうでない警報を区別できること |
| R8 | 自動封じ込め：変更系の高信頼イベントのとき、設定済みの資産で外向き通信の遮断（`egress`）またはネットワーク全体の遮断（`full`）を実行。再接続は自動では行わず、`zee restore` で手動 | `responder/sequence.py:handle`（`mode == "contain"` かつ `confidence == "high"` かつ `op_class == "change"` かつ `dry_run` でない）、`responder/cut_egress.py:cut_egress`、`responder/cut_full.py:cut_full`、`recovery/restore.py:restore` | [A09](https://top10.owasp.org/2025/A09_2025-Security_Logging_and_Alerting_Failures/) | 緩和策 [M1037 Filter Network Traffic](https://attack.mitre.org/mitigations/M1037/) | A09：“alerting to initiate active responses” が不足している状態を脆弱性とする。M1037：下り（egress）の通信を遮断・制限して攻撃者の行動を制限する |
| R9 | 証跡の改ざん検知：検知・遮断の記録をハッシュチェーン（SHA-256）で連結し、途中の書き換え・削除と先頭側の欠落を `corrupted`／`chain_break`／`head_missing` として報告 | `telemetry/events_log.py:EventLog`（追記処理）、`verify_chain` | [A09](https://top10.owasp.org/2025/A09_2025-Security_Logging_and_Alerting_Failures/) | [T1070 Indicator Removal](https://attack.mitre.org/techniques/T1070/) | A09：“The integrity of logs is not properly protected from tampering”／監査証跡に改ざん・削除を防ぐ完全性管理を付ける。T1070：存在の痕跡を減らすために、成果物を “delete or modify” する |
| R10 | 封じ込め証跡のエクスポート：記録済みの検知・遮断を、報告や相談に添付できるローカルファイル（json／txt）に書き出す。出力のハッシュ値と、元ログのチェーン検証結果を含む。送信はしない | `telemetry/report_export.py:build_export`、`attach_digest`、`cli.py:_cmd_export`、`mcp/server.py:query_containment_report`（読み取り専用） | [A09](https://top10.owasp.org/2025/A09_2025-Security_Logging_and_Alerting_Failures/) | — | A09：ログを攻撃後の分析（forensic analysis）に足りる期間・形式で保持し、ログ管理ツールが扱える形式で出力する |
| R11 | 当局向け報告書のまとめ：`zee export` の出力を、警察または個人情報保護委員会（PPC）への相談・報告に添付する文書（json／txt／html）にまとめる。送信はしない | `report/incident_report.py:build_incident_report`、`cli.py:_cmd_incident_report` | [A09](https://top10.owasp.org/2025/A09_2025-Security_Logging_and_Alerting_Failures/) | — | A09：インシデント対応・復旧の計画を持ち、インシデントを報告できるようにする（“Establish or adopt an incident response and recovery plan”） |

使い方の情報：

- 囮への接触を検知できる範囲は OS で違う。Linux は読み取り・オープン・変更を直接観測する。macOS と Windows は変更系を直接観測し、読み取りは R6 の canary URL（`ZEE_CANARY_BASE_URL` 設定時）が辿られたときに限る（[README の検知能力マトリクス](../README.md#mvp--動く囮トリップワイヤ)）。Windows は実機未検証。
- R9 のハッシュは鍵なしで、ホスト上の攻撃者が全体を再計算する場合と、ログ末尾の切り詰めは検知しない。保管場所を分けて運用する（[threat-model.md](./threat-model.md#evidence-store-and-containment-export)）。
- R2〜R4 は「囮への変更系の接触」を見る。ランサムウェア・ワイパー等が囮に触れた場合に動き、囮に触れずに動く攻撃は対象外。

## 表2　設計中・未実装の機能

表1に含まれない。実装・配線された時点で表1へ移し、一次情報を再確認する。

| # | 機能 | 状態と根拠 | OWASP 2025 | ATT&CK v19.2（想定する対象範囲） | 一次情報の該当記述（要旨） |
|---|---|---|---|---|---|
| D1 | 持ち出し承認：許可リスト外の宛先への送信（保護対象に触れた直後、または大きな送信）を保留し、別端末の署名があるまで通さない | `egress/engine.py:Engine`、`egress/pf.py`、`egress/signing.py`。`main` に統合済みだが **`zee watch`・CLI・通知・実ファイアウォールのどれからも呼ばれない**（既定 OFF）。設計：[design/egress-approval.md](./design/egress-approval.md) | — | [T1041 Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)、[T1048 Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)、[T1567 Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/) | 各技法：C2 チャネル・別プロトコル・Web サービス経由でのデータ送出。保留の判定は宛先と量で行い、プロトコルは問わない設計 |
| D2 | 自動封じ込めの許可（ON／OFF）状態：未許可は常に OFF として扱う | `responder/permission.py:decide`。`main` に統合済みだが **自動封じ込めがまだ参照しない**（CHANGELOG の Unreleased） | — | — | 対応づける項目は決めていない |
| D3 | macOS・Windows での読み取りの直接検知（macOS：Endpoint Security、Windows：SACL＋オブジェクトアクセス監査） | 未実装。現状は R6 の canary 経由のみ（README の検知能力マトリクス） | [A09](https://top10.owasp.org/2025/A09_2025-Security_Logging_and_Alerting_Failures/) | [T1552.001](https://attack.mitre.org/techniques/T1552/001/)、[T1005](https://attack.mitre.org/techniques/T1005/) | R5 を macOS・Windows に広げる位置づけ |
| D4 | Linux・Windows での動的検査（Docker・bubblewrap 等の隔離バックエンド） | 未実装。登録済みのバックエンドは macOS の `sandbox-exec` のみ（`gate/sandbox/backends.py`、[threat-model.md](./threat-model.md#sandbox-backend-matrix)） | [A03](https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/) | [T1552.001](https://attack.mitre.org/techniques/T1552/001/)、[T1546.004](https://attack.mitre.org/techniques/T1546/004/)、[T1543.001](https://attack.mitre.org/techniques/T1543/001/)、[T1547](https://attack.mitre.org/techniques/T1547/) | E12・E13 を Linux・Windows に広げる位置づけ |
| D5 | 署名つき脅威リスト（拒否リストの項目ごとの署名） | 未実装（将来の作業。[threat-list.md](./threat-list.md#integrity)） | [A08](https://top10.owasp.org/2025/A08_2025-Software_or_Data_Integrity_Failures/) | — | A08：ソフトウェアやデータが期待した出典のもので変更されていないことを、デジタル署名などで検証する |

## 更新のルール

- コードの該当箇所（`ファイル:関数`）が変わったら、本表も同じ変更で直す。ズレたらどちらかが古い。
- OWASP・ATT&CK の版が上がったら、項目名・技法 ID の存続と定義を再確認して「確認した版と日付」を更新する。技法 ID が統廃合された場合は、旧 ID を残さず新 ID に置き換える。
- 表1に載せる条件は、(1) `main` のコードがあること、(2) `zee` のコマンドから実際に呼ばれること、(3) OWASP・ATT&CK 側の該当記述を一次情報で確認できること、の三つ。

## 英語版

[owasp-attack-mapping.en.md](./owasp-attack-mapping.en.md)
