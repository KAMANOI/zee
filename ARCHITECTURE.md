# Zee — アーキテクチャ概要

> 🌐 English: [ARCHITECTURE.en.md](./ARCHITECTURE.en.md)

```
Project Status:
Early Architecture / Research Preview

This document describes the intended architecture of Zee.

It should not be interpreted as proof that every component is production-ready, independently validated, or suitable for deployment without expert review.
```

---

## 位置づけ

Zee は **侵入後（post-intrusion）** に作動する層を意図して設計されています。
ファイアウォール・EDR・パッチといった入口防御を置き換えるものではなく、それらをすり抜けて内部に到達した相手に対し、**侵入が即座にデータ窃取・運用への被害・気づかれない潜伏に結びつく可能性を下げる** ことを目的とします。

設計思想は「壊れないように作る」から「壊される前提で設計する」へ。これは Zee が新しく作った思想ではなく、現在のセキュリティ分野が広く向かっている方向と一致しています。

---

## 全体の流れ

下図は **MVP の実経路** です。`②番人（allowlist）` は将来の挿入点として図に明示しますが、現バックエンドでは未配線（watcher が触ったプロセスを報告しないため、現状は判定材料が来ません）。`引き込み・偽データ・偽内部ネットワーク・長期相関` は research-stage で、現リリースには含まれていません。

```
              ┌──────────────────────────────────────┐
              │  正規の業務トラフィック（巻き込まない意図）│
              └──────────────────────────────────────┘
                              │
侵入した攻撃者 ──▶ ①ふるまい観察（OS別 watcher）
                              │   ※ TrapEvent に op_class={read|change} を構造化フィールドで埋め
                              ▼
                  ┌─────────────────────────────────────┐
                  │  ②番人（allowlist）                  │
                  │   ※ 現バックエンドでは未配線          │
                  │     （プロセス特定不可・将来の挿入点） │
                  └─────────────────────────────────────┘
                              │
                              ▼
              ┌──────────────────────────────────────┐
              │ ⑥ ローカル通知（必須・ヒント付き）     │
              │    read  → 「正規ソフトの可能性」      │
              │    change → 「危険度が高い可能性」      │
              ├──────────────────────────────────────┤
              │ ⑦ webhook 送信（非同期・best-effort）  │
              ├──────────────────────────────────────┤
              │ ⑧ mode 解決（contain / staged / notify）│
              ├──────────────────────────────────────┤
              │ ⑨ 自動遮断ゲート（全条件 AND）          │
              │    mode == "contain"                   │
              │  ∧ confidence == "high"                │
              │  ∧ op_class == "change"  ← v4 で追加   │
              │  ∧ not dry_run                         │
              │  ↓ 全て満たす                          │
              │    cut（OS別 full / egress）           │
              │  ↓ いずれか欠ける                       │
              │    遮断せず・通知のみ                  │
              ├──────────────────────────────────────┤
              │ ⑩ レイテンシ記録（events / metrics 各 jsonl）│
              └──────────────────────────────────────┘

   read 接触：⑨ で op_class 条件に弾かれ、自動遮断には進まない
              （通知ヒントから人間が `zee cut <asset_id>` で手動遮断）
   change 接触：上記 4 条件をすべて満たすとき自動遮断
```

具体的な実装範囲・状態は、本文書末尾の「実装の現在地」表で詳述します。

---

## 各層の役割

| 層 | 役割 | Status |
|---|---|---|
| ① ふるまい観察 | 選ばれたプロセス・ファイル・ネットワークの挙動を観察し、疑わしい逸脱を識別する | Mechanism public |
| ② 番人（安全装置） | 検知と引き込みの間に立ち、確定的なゲートにより誤作動の発生確率を下げる | Mechanism public |
| ③ 偽データへのリダイレクト | 特定の構成において、選ばれたアクセス試行を目印つきの偽データへリダイレクトまたは置換できる | Research-stage |
| ④ 偽内部ネットワーク | 本物そっくりの偽環境で探索のコストと時間を引き上げることを目指す | Research-stage |
| ⑤ 長期相関 | 数ヶ月スパンの潜伏型攻撃を時間をまたいで結びつけて検知する研究方向 | Research-stage |

各 Research-stage 項目は、効果がまだ独立に検証されていません。

---

## 安全性の原則（誤作動の最小化）

侵入後の層で最大のリスクは、正規のプロセスや社員を誤って罠に引き込むことです。Zee はこの risk を **最小化** することを目指します（「ゼロ」は約束しません）。

- 検知と引き込みの間に **二重の安全装置** を置く
- 「誤作動の最小化」と「重大な攻撃の検知」という相反する要件を、1 つの仕組みに詰め込まず **役割を分けて** 両立させる
- 判定は AI の裁量ではなく **確定的なルール** で行う

具体的な作動条件・閾値は実装段階で詰めるパラメータであり、現段階では研究中のものを含みます。

---

## プライバシーの原則

現 MVP は **攻撃者の IP を取得・保存しない設計** です。watcher / responder / telemetry のいずれの経路でも、IP アドレスや個人を特定できる情報を扱いません。記録するのは「どの囮に・いつ・どの種類の接触があったか」と、自動応答が走った場合の遮断レイテンシだけです。

**canary トークンについての境界の明記**：Zee 本体は canary URL の HTTP リスナーを内蔵していません。読み取り検知用の canary URL は、operator が指定した外部エンドポイント（自前 webhook 受信器・Canarytokens.org・AWS Lambda 等）で発火します。攻撃者がその URL を実行した瞬間、**発信元 IP は外部エンドポイント側で捕捉されえます**が、それは Zee の外側の領域であり、operator が選んだ外部エンドポイント運営者のプライバシー方針の責任範囲です。token_id 自身は `secrets.token_urlsafe` で生成され、内部で操作者情報と紐付きません。

**v0.2 における canary の配線状況**：`CanaryTokenRegistry`（`src/zee/decoy/canary_token.py`）は seeder から呼ばれ、env / credentials / notes テンプレートに canary URL を自動埋め込みします。ssh_key は OpenSSH 形式の都合で対象外です。配線は `ZEE_CANARY_BASE_URL` 環境変数で有効化します（未設定なら埋め込みも発生せず、macOS / Windows のデコイ読み取りは観測されません・既定で安全側）。registry は `~/.local/state/zee/canary_tokens.jsonl`（0600）に永続化され、再起動後も decoy_path → token の対応を保持します（同じ囮に対しては同じ URL を再利用・幂等性）。埋め込み行は `canary` / `tripwire` / `zee` / `decoy` のような Zee 由来語を一切含みません（テンプレート構造として「rotation policy」「MONITORING_ENDPOINT」「partner integration」等の自然な名前を使用）。`about:zee/c/...` fallback は v0.2 で撤去し、base_url 未設定で発行を試みると `RuntimeError` を上げます。

`policy/allowlist.py` の `ip_cidrs` / `is_protected(ip=...)` は、現在の watcher バックエンドからは一切呼ばれていません。将来 IP を扱う relay/correlation フェーズへの予約席であり、現リリースでは「Zee が攻撃者 IP を扱う」と読める実装は存在しません。

将来 IP 取得経路を追加する場合は、平文保存は採用しません。素のハッシュ化も IPv4 では総当たりで逆引き可能なため採用しません。Zee の脅威モデル（攻撃者がホスト上にいる前提）ではホスト上に鍵を置く keyed HMAC は逆引き耐性が崩れうるため、**末尾オクテット切り捨て**（IPv4 /24、IPv6 /48）を第一候補とします。HMAC を採るなら鍵はホスト外に置く方針です。

その他の方針：
- 蓄積データは期限を過ぎると自動的に削除する（設計目標）
- 相関を追加する場合は「個人」ではなく「セッション（行動の主体）」を軸とする

これらは設計目標として書いています。実装の各段階で同じ原則が守られているかは、実装側のドキュメントで確認できます。

---

## 依存と配布

- 現リリースは Python 標準ライブラリのみで動作します（第三者ランタイム依存ゼロ・TOML パースは `tomllib`）
- このリポジトリにある資料はすべて MIT ライセンスのもとで公開します

---

## Zee 自身の自己防衛

responder の `cut_full` / `cut_egress` と recovery（`zee restore`）は OS レベルの回線遮断・復旧権限を要求するため、Zee 自身が侵入後の攻撃者にとって高価値な標的になりえます。攻撃者が Zee の構成・遮断バックエンド・ログを読み書きできれば、検知をすり抜けたり、遮断を巻き戻したりできます。

### 現リリースで対応済み

- **設定ファイル保護**：`policy/allowlist.py` の JSON 読み込みは、ファイルおよび親ディレクトリのグループ・他者書込権限を起動時に検査し、緩い場合は読み込みを拒否します（allowlist の改ざんを既に防止）。
- **囮自己消失検知**：Linux backend が `IN_DELETE_SELF / IN_MOVE_SELF` を購読し、囮ファイル自身の削除・改名を高信頼イベントとして上げます。
- **ログのパーミッション（v4 任意 2 で実装）**：`telemetry/events_log.py` のログディレクトリは 0700、`events.jsonl` / `metrics.jsonl` は 0600 で作成します。decoy_path が平文で記録されるため、非 root の同居ユーザーがログを読んで囮位置を列挙する経路を塞ぎます。**root 相当の攻撃者には依然読まれます** が、それは下記の権限分離の話に移ります。

### 既知の弱点（Limitations にも明記）

- **`zee restore` に認証がない**：CLI を実行できる者（root でなくても、同じユーザーセッションで実行できれば誰でも）が遮断を解除できます。手動リカバリ＝自動再接続なしという安全側の設計の裏面で、侵入後の攻撃者がホスト上でシェルを取れば遮断を巻き戻せます。今回はあえて認証を入れていません（HIROKI 一人運用前提の MVP）。マルチユーザー環境で運用する場合は、`zee restore` を sudo / ファイル権限で囲うか、専用ユーザーで運用する等の包囲策が必要です。

### 設計意図として将来フェーズに引き継ぐもの

- **権限分離**：watcher / policy / responder を別プロセス（または別ユーザー）に分け、最小権限で動かす。watcher は遮断権限を持たず、responder は囮イベントだけを契機に動く。
- **ログ改竄検知**：イベントログを追記専用ファイルシステム機能（macOS の SIP / Linux の append-only attribute）で守るか、定期的にハッシュチェーンを取って改ざんを検知できる構造にする。
- **`zee restore` 認証**：マルチユーザー想定で運用する場合、PAM / 公開鍵 / FIDO2 等を経由した認証層を入れる。MVP のスコープには含めない。

---

## 研究方向

罠多様化（trap diversification）の研究方向については、別ファイルで扱います：
→ [RESEARCH.md](./RESEARCH.md)

そこに含まれるアフィンコラッツ研究は、**罠の暗号学的保証や封じ込め保証ではなく**、研究上の方向性として記述しています。

---

## 実装の現在地

| 構成要素 | 実装状況 | 場所と備考 |
|---|---|---|
| ① ふるまい観察（囮トリップワイヤ） | ✅ Implemented | `src/zee/watcher/` — Linux は inotify で open/read/modify を直接観察。macOS は kqueue で変更系を観察＋`ZEE_CANARY_BASE_URL` 設定時は seeder が canary URL を decoy に埋め込み、operator の外部エンドポイントで read 発火（out-of-band・Zee 本体には戻らない）。Windows も同様。Windows 実機未検証 |
| ② 番人（安全装置） | 部分実装 | `src/zee/policy/` — allowlist データ構造実装済み。responder への連結（contain 前に allowlist で降格判定）は次フェーズ。multi-signal trap gate も次フェーズ |
| ③ 偽データへのリダイレクト | Research-stage | 設計のみ。実装は別途検討 |
| ④ 偽内部ネットワーク | Research-stage | 同上 |
| ⑤ 長期相関 | Research-stage | RESEARCH.md（CDS / アフィンコラッツ研究）参照 |
| 応答（自動封じ込め） | ✅ Implemented | `src/zee/responder/` — OS 別 full・egress 切断・**既定 dry_run** |
| 通知 | ✅ Implemented | `src/zee/notifier/` — ローカル必須・webhook 任意 |
| 復旧 | ✅ Implemented | `src/zee/recovery/` — `zee restore <asset_id>` 手動のみ |
| 計測 | ✅ Implemented | `src/zee/telemetry/` — JSON Lines・レイテンシ・誤検知マーカー |

導入手順とコマンドは → [README.md の MVP セクション](./README.md#mvp--動く囮トリップワイヤ)

---

<sub>各層の詳細・後続フェーズの追加は順次行います。</sub>
