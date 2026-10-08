# 照会型カナリア — 設計書（非公開メモ・push禁止）

> **この文書・このブランチは代表の採否判断が出るまで `git push` しないこと。**
> 既存の Zee README・LP の「過剰主張をしない」方針をこの文書にも適用する：
> 効果を断定する表現（「見破られません」「必ず検知できます」）を使わず、
> 「確認済み」と「推測」を常に分けて書く。トラップの作動条件・閾値を公開物に書かない方針
> （2026-05-29）に揃え、本書は非公開メモのまま運用する。

## 0. 目的（指示書より）

流出しうるデータに、処理（名寄せ・突合・到達確認などのクリーニング操作）をされると
こちらが管理するエンドポイントへ照会が飛ぶおとり値を混ぜる。攻撃者がデータを処理した
時刻・接続元を記録し、逆探知の起点として当局・報告窓口へ渡せる形にする。無害化はしない
（[[zee-no-active-defense-report-to-authorities-policy]]・Zeeの既存方針と整合）。

既存の `src/zee/decoy/canary_token.py` は「人間がURLを踏む／curlする」ことを発火点に
する。本件は「自動処理パイプラインがDNS解決・SMTP到達確認・HTTP取得をする」ことを
発火点にする点が異なる、新しい発火トリガーの追加。既存コードは一切変更していない。

## 1. 重複確認（着手前・指示書の要求）

- **`src/zee/decoy/canary_token.py`（既存）**：operator-controlled https base_url・
  jsonl永続化・出自語を含むトークンの引き直し、の3点は完全に再利用できると判断し、
  新モジュール `src/zee/decoy/query_canary.py` から `CanaryTokenRegistry` を呼ぶ形に
  した（再実装なし）。相違点は①発火トリガー（読む vs 処理される）②値の形（ファイル内の
  URL vs メール/ホスト名/URL単体）。
- **`~/projects/zee-decoy-pii-dilution`（進行中・別指示書・未push）**：ダミー個人情報
  レコード生成。目的は価値毀損であり検知ではない（設計書冒頭に明記済み）。§6で
  「メールアドレスを選択肢Bとして自分管理ドメインにする」案が代表確認事項のまま保留に
  なっており、**本書のメール型照会カナリアはその選択肢Bの実装そのものに相当する**。
  重複ではなく、ダミー混入案が止めていた1点（メールの実装）を本指示書が担当する関係。
  台帳の考え方（目印をレコード自体に持たせず別ファイルに置く）は揃えたが、
  ダミー混入側のHMAC台帳（`ledger.jsonl`、record_hmac）とは**ファイル・スキーマを
  共有しない**（§4で理由を説明）。ダミー混入のコード・ブランチには一切触れていない。
- `zee_trace_spec_20261007` 相当のファイル・Obsidianノートは本機（`~/projects`配下・
  このClaude Codeのメモリ）からは発見できなかった。**情報なし**として扱う。
- ai-virtual-corp 内の「被ハッキング用ファンサイト」構想（2026-10-01検討中）との受け口
  共用可否：decisions.md・WORKLOG を検索したが該当エントリが見つからなかった。
  **情報なし**（代表確認事項）。

## 2. 火種にできる値の種類

| 種類 | 形 | 発火条件 | 発火の速さ・確実さ |
|---|---|---|---|
| **hostname（推奨・既定）** | `<token>.<domain>` | 名前解決（DNS lookup）だけで発火。TCP接続・HTTP取得は不要 | **最速**：多くのリンク検証・到達確認ツールは、接続を試みる前に必ず名前解決をする。相手の処理速度に依存しない（指示書補足2） |
| **email** | `<token>@<domain>` | メール到達可能性チェック（MXレコード問い合わせ、または実際のSMTP RCPT TO）で発火 | hostname型と同じDNS発火に加え、本物のSMTP接続まで追う実装ならさらに強い証跡（接続元IP）が取れる |
| **url** | `<base_url>/<token>` | HTTPリクエスト（リンクチェッカー・プレビュー生成）で発火 | 相手がURLを実際にGETする実装の時だけ発火。DNSだけ見て終わるツールには効かない |

**確認済み**：DNS解決は多くの処理の最初の一歩であり、相手がURLを実際にfetchするか
どうかに依存しない、という一般的な技術的事実（HTTPクライアントは接続前に必ず名前解決
する）。**推測**：攻撃者が使う具体的な「クリーニングツール」がどこまで処理するか
（DNSだけ見るか、SMTP接続まで試すか、HTTPを実際にGETするか）は対象のツールごとに
異なり、本書では確認していない。このため**hostname型を既定・主系**とし、email/url型は
「相手がより深く処理した場合に追加の証跡が取れる」補助系とする。

住所・氏名の文字列そのものは発火しない（指示書補足1と同じ理由：ネットワークに出ていく
必要がない値は照会を生まない）。したがって本書の火種は、ダミー混入案§6の
「メールアドレス」の欄にのみ接続する。

## 3. トークンの安全性（試作中に発見・修正した実装バグ）

試作の自己テスト（`tests/test_query_canary.py::test_hostname_value_shape`）で、
`CanaryTokenRegistry` 自身の `token_id`（`secrets.token_urlsafe(16)` 生成＝大小混在・
`-`・`_` を含む）を直接 hostname/email の値として埋め込むと、以下が壊れることが判明した：

- DNSラベル規則（英数字とハイフンのみ、先頭はハイフン不可、大文字小文字を区別しない
  ためDNS照会ログでは大文字情報が失われる）
- メールのローカル部に先頭 `-`/`+`/`=`/`@` が来ると、台帳や生成結果をExcel/スプレッドシート
  で開いた利用者側のCSVインジェクション事故（指示書要求6）の引き金になりうる

修正として、hostname/emailには**別の、独自生成の安全なトークン**
（`secrets.token_hex(16)` = 小文字16進32文字、必ず英数字始まり、`=+-@`を含まない）を
使い、`CanaryTokenRegistry.issue_for_decoy()` の `decoy_path` キーとしてこの安全な
トークンそのものを渡して永続化する（`token.token_id` は使わない）。url型は値がURLの
パス部分に留まるため既存の `token_id` のままで問題ない。

16進アルファベット（0-9a-f）は `zee`/`canary`/`tripwire`/`decoy`/`hdr`/`honeypot`/
`trap`/`sting` のいずれの出自語も構成できない（必要な文字 z/n/r/y/o/t/i/p/w/s/g のうち
どれも16進文字に含まれない）ため、既存の `_ORIGIN_WORDS` 引き直しループは不要（テストで
確認済み）。ドメイン名自体には同じ出自語チェックを適用する（§7）。

## 4. 除外台帳（代表確認事項4への回答）

**既存の `canary_tokens.jsonl`（`CanaryTokenRegistry` が既に書いている永続化ファイル）
を、そのまま除外台帳として再利用する。新しいファイル形式は作らない。**

- `issue_for_decoy(decoy_path, purpose)` は `{decoy_path, token_id, base_url, purpose,
  created_at}` を1行ずつjsonlに追記する（既存実装・変更なし）。hostname/email型では
  `decoy_path` に§3の安全なトークン文字列そのものを格納する。
- 利用者（代表・運用者）自身の名寄せ・到達確認パイプラインは、処理対象の値を触る前に
  `is_known_value(registry, value, kind)` を呼べば、その値が自分が発行した照会カナリア
  かどうかを判定できる。
- **独立レビューで発見・修正した不整合（2026-10-09）**：`CanaryTokenRegistry.
  _load_from_file()` は、レコードの `base_url` が現在設定中の `base_url` と一致しない
  行を無条件で読み飛ばす（url型のWebhook URLが失効したことを表す、既存の意図的な設計・
  `test_rehydrate_skips_records_with_different_base_url` で保証）。email/hostname型は
  そもそも`base_url`と無関係（Webhook URLを含まない）にもかかわらず同じフィルタを
  経由していたため、運用者が`ZEE_CANARY_BASE_URL`（Webhook受け口）をローテーションする
  と、既発行のemail/hostname型カナリアが除外判定から消え、運用者自身のパイプラインが
  自分のカナリアに誤発火する不整合があった。修正：email/hostname型の除外判定は
  `registry`の内部マップ（base_urlでフィルタ済み）を経由せず、`canary_tokens.jsonl`を
  直接読んで`decoy_path`の一致だけを見る（`query_canary.py::_decoy_path_ever_persisted`）。
  url型は既存どおりbase_url依存のままでよい（Webhook先が変われば古いURLが死ぬのは
  正しい挙動のため）。回帰テスト：
  `test_email_exclusion_survives_base_url_rotation`。
- ダミー混入案の `ledger.jsonl`（HMAC台帳）とは**意図的に別物**：あちら台帳はHMACで
  「台帳自体が流出しても実データを逆引きできない」ことを狙っている（守るべき対象＝
  ダミーが紐づく実データの存在そのもの）。照会カナリアの値はそもそも乱数トークンで実データ
  と無関係なので、台帳が流出しても逆引きされる実データが無く、HMAC化する理由がない。
  指示書補足4の「同じ考え方（目印はレコード自体に持たせず別の場所に置く）」は、
  「カナリア値自体に"これは囮"という印を付けない・判定材料は別ファイルに置く」という
  コンセプトの一致で満たしており、ファイル形式を無理に合わせると却って
  `canary_tokens.jsonl` が持つ既存の権限（0600）・既存のテスト網を失う。

## 5. 受け口の構成とコスト

### 5.1 設計方針

`canary_token.py` の既存ドキュメント方針（「Zee自身はHTTPリスナーを持たない。運用者が
信頼する任意の受け口を指す」）を継続する。本書の受け口実装（`examples/
query_canary_http_receiver.py`・`examples/query_canary_dns_receiver.py`）は、
`zee` パッケージ本体（`src/zee/`）ではなく `examples/` に置く参考実装であり、
運用者（HDR）が実際にデプロイする先は別途選ぶ。

受け口は相手に何も「させない」ことを以下のように定義する（代表確認事項）：
- HTTP：204・空ボディ・`Set-Cookie`/`Location`/キャッシュ系ヘッダーなし。接続元の
  その後の挙動に影響する情報を一切返さない。
- DNS：NXDOMAIN（RCODE=3）のみ。A/AAAAレコードは返さない（返すと相手がそのIPへ
  さらに接続する次の一歩を誘発してしまうため）。

### 5.2 コスト（doc-fetcher 1件・確認済みと推測を分離）

| 項目 | 金額・条件 | 確認度 |
|---|---|---|
| 汎用.comドメイン新規取得 | 年額 **$10.46**（Cloudflare Registrar、WHOISプライバシー・DNSSEC込み） | 確認済み（出典：Cloudflare .COM Domain Pricing） |
| Cloudflare DNS 無料プランのクエリログ（送信元IP・時刻） | **無料プランでは取得不可**（Enterprise限定のLogpushのみ） | 確認済み（出典：Cloudflare DNS Analytics ドキュメント） |
| 自前権威DNS（PowerDNS/BIND）でのクエリログ | `log-dns-queries=yes` 等の設定で送信元IP・時刻を記録可能・無料（OSS） | 確認済み（出典：Self-Hosted DNS Logging Guide）。ただしVPS等の実行環境費が別途必要（**推測**：月$5〜15程度、具体的な1社の見積りは未取得） |
| Cloudflare Workers 無料プラン | リクエスト数 20万/日・ログ保持 **3日間** | 確認済み（出典：Cloudflare Workers Pricing） |
| Thinkst Canarytokens（canarytokens.org） | **無料・制限なしで利用可**。記録情報：送信元IP・User-Agent・時刻・（HTTP系は）位置情報。セルフホスト版（OSS・AGPL）も無料 | 確認済み（出典：Canarytokens公式ドキュメント／Best Free Canary Token Providers） |

**総額の試算（推測を含む）**：ドメイン年$10.46 ＋ 受け口の実行環境（無料枠に収まる
設計なら$0、収まらない場合はVPS月$5〜15程度・推測）。DNSクエリ単位のログが必須要件
なら、Cloudflare DNSの無料プランだけでは満たせない（確認済み）ため、
「①自前の小さなDNSサーバーをVPS/無料枠コンテナで建てる」か「②Thinkst
Canarytokensのセルフホスト版を使う」のどちらかが必要（代表確認事項）。

### 5.3 既存の囮サイト構想との共用

2026-10-01検討中とされる「被ハッキング用ファンサイト」の受け口との共用可否は、
ai-virtual-corp の decisions.md・WORKLOG を検索したが該当記録が見つからず
**情報なし**（代表確認事項）。

### 5.4 Thinkst Canarytokens を使う選択肢（推奨・代表確認事項）

自前のDNS/HTTP受け口（§5.1・本書の試作）をゼロから運用する代わりに、
**Thinkst Canarytokens（無料・OSS・DNS token/Web bug token を標準提供）をそのまま使う**
選択肢がある。利点：運用コストが実質ゼロ、実装済みで枯れている、ヒット時の記録項目
（送信元IP・時刻・User-Agent）が本書の要求と一致する（確認済み）。欠点：当局への
証跡提出を前提とする本件では、ログの保存期間・エクスポート形式・chain of custody
（誰が記録を保持し改ざんされていないと言えるか）を第三者サービスに依存することになる
——この点は確認できておらず、**自前ホストかThinkst併用かは代表判断**とする。
本書の試作（examples/の2ファイル）は「自前で持つ場合」の最小実装として用意した。

## 6. おとりの生成と配置

- `src/zee/decoy/query_canary.py::issue_query_canary(registry, kind, purpose, *,
  domain=None)` を呼ぶと、ダミー混入のCLI（`zee dilute generate`、進行中・別指示書）が
  生成するCSVの「メール列」「URL/Webサイト列」に差し込める1行の値が返る。
- 本指示書の範囲では `feat/decoy-pii-dilution` のコードには一切触れない（範囲外・
  「触ってよい範囲」の指定どおり）。統合はインターフェースの提案のみ：ダミー混入側の
  `--email-mode user-domain` を実装する時に、メールアドレス生成部をこの
  `issue_query_canary(registry, "email", ..., domain=...)` に置き換えれば接続できる、
  という申し送りに留める。

## 7. ドメイン名の目印対策

既存の `_ORIGIN_WORDS`（`zee`/`canary`/`tripwire`/`decoy`、トークン文字列用）に加え、
本書では運用者が取得する**ドメイン名自体**にも同種の語（`hdr`/`honeypot`/`trap`/
`sting`を追加）が含まれないことをコードでチェックする（`query_canary.py::_check_domain`、
テスト済み）。トークンのチェックとドメインのチェックは別の関数・別の対象であることを
明記する（トークンは引き直しで解決できるが、ドメインは運用者が買う前に決める必要がある
ため、チェックは「拒否してやり直させる」形にした）。

## 8. 試作の範囲（stdlib のみ・依存ゼロ方針継続）

- `src/zee/decoy/query_canary.py`：値の生成（email/hostname/url）・ドメインの出自語
  チェック・除外判定。
- `examples/query_canary_http_receiver.py`：url型の参考受け口。`http.server`のみ。
- `examples/query_canary_dns_receiver.py`：hostname型の参考受け口。生DNSパケットを
  `socket`で解釈・NXDOMAINのみ返す最小実装（本格的な権威DNSサーバーの代替ではない）。
- `tests/test_query_canary.py`：21件。値の形・ドメイン拒否・除外台帳の永続化後の再読込・
  base_urlローテーション後も除外判定が生き残ること・HTTP受け口への実際のリクエスト
  到達とログ記録（GET/POST/OPTIONS）・DNS受け口への実際のクエリ到達とNXDOMAIN応答
  （ANCOUNT=0・応答長の厳密一致まで確認）・ログ記録・壊れたDNSパケットを受けても
  サーバーが死なず次のクエリに応答すること、を実機（localhost）で検証。
- 社内独立レビュー（reviewer・2026-10-09）：高0件・中1件（上記、修正済み・回帰テスト
  追加済み）・低3件（DNS異常入力の自動回帰テスト欠落／HTTP受け口がOPTIONSを記録
  しない／NXDOMAIN応答の厳密なアサート不足）。低3件も全て修正・テスト追加済み。

### 未対応・次フェーズへの申し送り

- 本番運用の権威DNSサーバー（PowerDNS/BIND等）・本番HTTP受け口（Cloudflare
  Workers等）への実デプロイは代表判断後（§9 PENDING）。
- SMTP RCPT TOレベルの到達確認に対応する最小SMTPサーバー（受け口候補の1つ、email型の
  証跡をより強くする）は未試作（v1はDNS/HTTPのみ）。
- §6の統合（ダミー混入CLIへの接続）は申し送りのみで未実装。
- DNS受け口はクエリ内のドメイン名圧縮（0xC0ポインタ）を実装していない（最小参考実装の
  既知の限界。本番は圧縮に対応した本格的な権威DNSサーバー（PowerDNS/BIND）を使う前提
  のため実害は小さいが、§5.4のThinkst Canarytokens併用案はこの限界自体を回避できる）。

## 目的判定（事前チェックへの回答）

- **問1**：Zeeの目的カード(d)に明記の関門ではないが、カード(c)の方向性
  （第4原則「他者の弱さを利益に変えない」＝攻撃の採算を崩す、第6原則「個を越えて繋がる」
  ＝記録を当局へ渡す形で社会につなぐ）に資する新しい発火トリガーの追加。既存の関門
  （第三者skill審査等）とは独立。
- **問2**：目的カード(b)「過剰主張をしない」「無害化はしない」は、本書の記録項目を
  「照会の事実・時刻・接続元・どのおとりか」に限定し、相手に何も送らない設計（§5.1）で
  守っている。「Zee自身はHTTPリスナーを持たない」という既存原則は、受け口を
  `zee`パッケージ本体でなく`examples/`に置くことで維持した。減らす操作は含まない
  （新規追加のみ）。
- **問3**：資産を残したまま同じ狙いを満たす代替＝Thinkst Canarytokens（§5.4）を使い
  自前受け口を持たない案。これは「採らない理由」ではなく実際に有力な選択肢として
  代表確認事項に挙げた（本書の試作はどちらを選んでも無駄にならない最小実装として用意）。
