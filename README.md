# Zee

[![Tests](https://github.com/KAMANOI/zee/actions/workflows/test.yml/badge.svg)](https://github.com/KAMANOI/zee/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](./pyproject.toml)

> 🌐 English: [README.en.md](./README.en.md) ｜ 🌐 LP: https://kamanoi.github.io/zee/

> Zee は、高度AI時代において、防御準備が追いついていない組織や個人が、最初の一歩を踏み出すためのオープンプロジェクトです。

```
Project Status:
Early Public / Research Project — v0.13.3

Zee is not a production-ready security product.

Zee does not guarantee protection, containment, prevention of data theft, or detection effectiveness.

Implemented (v0.13.3): entry gate (zee gate), decoy tripwires with opt-in containment (observe-only by default), containment-evidence export and incident-report bundle.
What has been verified, under which conditions, and what has not: docs/verification/
```

---

## なぜ Zee があるのか

社会の不安を減らしたい。これが Zee の出発点です。

AI は素晴らしい技術です。しかし攻撃側もそれを使えます。問題は AI そのものではなく、社会の準備が追いついていないこと。

守りたいのは、安心して暮らせる社会、人と人の信頼、まじめな企業の努力、善意が無意味にならないこと。Zee が有名になることが成功ではありません。社会が安定すれば成功です。誰かがより良い方法を作るなら、それでも良いと考えています。

---

## 次世代AI時代の備え

機械の速度で動く攻撃が現れました。脆弱性の発見と武器化が、安く・速く・大量になっています。

以下はいずれも AI を開発する Anthropic 自身が公表した数字です。

- 旧世代モデルが数百回中わずか 2 回しか攻撃コードに仕立てられなかったブラウザ（Firefox の JavaScript エンジン）の脆弱性を、新世代モデルは **181 回** 動作する攻撃コードに変えた
- **27 年間**、専門家監査と自動テストを生き延びた OpenBSD の欠陥を、**約 1,000 回の自動試行・総額 2 万ドル未満** で発見した
- 横断的な調査では **23,000 件超の脆弱性候補** が見つかり（うち独立検証は約 1,752 件）、約 **50 億台** の機器に影響する暗号ライブラリの致命的欠陥（CVE-2026-5194）もこの流れで発見された

出典：[Mozilla との Firefox セキュリティ連携](https://red.anthropic.com/2026/firefox/)（181 回の数字の出典）／ [Claude Mythos Preview](https://red.anthropic.com/2026/mythos-preview/)（OpenBSD 27 年間・約 1,000 回・2 万ドル未満の数字の出典）／ [Project Glasswing: An initial update](https://www.anthropic.com/research/glasswing-initial-update)（23,019 件・独立検証 1,752 件の数字の出典）

これらは **攻撃側の能力** を示す数字です。Zee はそれを止める道具ではありません。
Zee が時間を稼ぐ対象は、機械速度の攻撃そのものではなく、**人間〜半自動の侵入後活動**（侵入が成功した後、攻撃者または攻撃 AI が偵察・横移動・データ窃取に進む段階）です。完全自動で秒単位に動ききる相手の前では、Zee の有用範囲は限られます（Limitations 参照）。

Zee が向き合っているのは、**攻撃能力の進化速度** と **防御準備の普及速度** の差です。Zee は、その差を少しでも埋めることを目指します。

---

## Zee とは何か

「侵入されるな」ではなく **「盗まれるな」** を出発点にしています。さらに言えば **「時間を稼ぐ」** ——本職の対策や対応が届くまでの猶予を増やすことを目指します。

これは **設計目標** です。「防御率○%」のような数値の性能主張はしません。実施した検証は、条件・対象版・結果・未実施の範囲を分けて [docs/verification/](./docs/verification/README.md) に載せています。

**設計の約束（3点）：**
- **侵入後の封じ込めと時間稼ぎ** — 入口防御の代わりではなく、侵入が成功した後の段階に1本足す層です
- **既定は観測のみ** — 実際の遮断は、利用者が `response_mode: auto` を選び `dry_run: false` にしたときだけ動きます
- **誤検知で業務を止めにくい設計** — 自動遮断は、正規ソフトが普通やらない「変更系の接触」だけを根拠にします。読み取り系は通知のみです。これは設計上の約束で、通常運用での誤検知率は測定していません

**Zee ではないもの：**
- AI を倒すプロジェクトではない
- 国家サイバー兵器ではない
- 完全防御システムではない
- アフィンコラッツの普及活動ではない

**Zee の目的：** 防御ゼロ状態を減らすこと。

---

## Zee でできること

現段階の Zee が提供するのは、以下です。

- **Starter Guide** — 何から考え始めればよいかの最初の一歩（[STARTER_GUIDE.md](./STARTER_GUIDE.md)）
- **事業者向けガイド** — 次世代AIの脅威に不安を感じる事業者向け・専門用語ゼロ・併用すべき防御策と相談先まで案内（[business_guide.html](https://kamanoi.github.io/zee/business_guide.html)）
- **Architecture 概要** — 設計の意図と各構成要素の役割（[ARCHITECTURE.md](./ARCHITECTURE.md)）
- **Research note** — 研究方向としての CDS とアフィンコラッツ研究（[RESEARCH.md](./RESEARCH.md)）
- **入口ゲート** — AIスキル / MCP / npm / PyPI / VS Code 拡張を、導入する前に静的スキャン（`zee gate`・[docs/gate.md](./docs/gate.md)）
- **MVP 実装** — 軽量な囮トリップワイヤ＋自動封じ込め（`src/zee/`・**既定 dry_run**）
- **検証記録** — 実施した検証の条件・対象版・結果・未実施の範囲（[docs/verification/](./docs/verification/README.md)）
- **封じ込め証跡のエクスポート** — 記録済みの検知・遮断の記録を、報告や相談に添付できるローカルファイルに書き出す（`zee export`・送信はしない・[法制度との関係](#法制度との関係2026-10-01)）
- **当局向け報告書のまとめ** — `zee export` の出力を、警察または個人情報保護委員会（PPC）への相談・報告に添付する文書（json/txt/html）にまとめる（`zee incident-report`・送信はしない）

---

## 入口ゲート — 入れる前に、見る

公開されている AI スキルや MCP サーバー、npm / PyPI パッケージには、エージェントを外部へ開かせる**プロンプトインジェクション**が仕込まれていることがあります。いま最も大きい攻撃面の一つです。Zee の入口ゲートは、**導入する前に**その成果物を隔離下（実行しない）で静的に検査し、不審な指示・過剰な権限要求・既知の脅威リスト該当を洗い出して、入れる／入れないの判断材料を返します。

```bash
# 導入前にスキャン（Claudeスキル / MCP / npm / PyPI / VS Code 拡張を自動判別）
zee gate add ./some-skill

# 既存スキャナ（Semgrep / SARIF: Snyk・CodeQL 等）の結果も取り込んで合算
zee gate add ./pkg --import-scan report.json

# 配布後のすり替え（Rug Pull）を後から監視
zee gate audit
```

静的検査であり、すべての悪意を検出できるわけではありません（正直に）。Semgrep / Snyk / Socket を置き換えるものではなく、それらと**併用する一層**です。GitHub Action として CI / pre-install に組み込めます。詳細は [docs/gate.md](./docs/gate.md) ／ 脅威リストの形式は [docs/threat-list.md](./docs/threat-list.md) を参照してください。

---

## MVP — 動く囮トリップワイヤ

`src/zee/` に MVP の実装があります。**既定では dry_run で動き、実際の遮断は行いません。** 資産プロファイルで `response_mode: auto` を明示し `dry_run: false` にしたときだけ、自動遮断（contain）が走ります。

> **v0.12.0 以前で `cut_method: egress` を macOS・Windows でお使いの方へ（2026-10-15）** — v0.12.0 以前の外向き遮断は、macOS では規則を入れるアンカーが標準の `/etc/pf.conf` から参照されず、Windows では `netsh` が規則を受け付けず、**どちらも通信を止めていませんでした**（Windows は遮断を「失敗」と表示していました）。v0.13.0 で修正し、GitHub の仮想ランナー（macOS・英語版 Windows）で通信が止まって復旧で戻ることを確認しました（macOS は実機1台でも v0.13.0 の規則で確認）。**v0.13.0 以降に更新してください。**

> **外向き遮断と IPv6（v0.13.1・2026-10-16）** — v0.13.0 までは、iptables の経路（nft の無い Linux）と Windows の経路が IPv4 の規則だけを入れ、**IPv6 の外向き通信を止めていませんでした**（遮断の結果に `IPv6 NOT blocked` と出ていました）。v0.13.1 で、iptables の経路は同じバックエンドの ip6tables にも規則を入れ（入れられなければ遮断は「失敗」）、Windows は同じ規則に IPv6 の範囲を足しました。どちらの経路も、ループバック・リンクローカル（`fe80::/10`）・ULA（`fc00::/7`）・リンク内マルチキャスト（`ff02::/16`）以外の IPv6 を止めます。Linux（名前空間内の nft・iptables nf_tables 版・legacy 版）では IPv6 の通信が止まって復旧で戻ることを実測しました。**Windows は規則が入り読み直しで一致することまでを確認し、IPv6 の通信が止まることは未確認です**（ランナーに IPv6 の外向き経路が無いため）。**v0.13.1 以降（最新は v0.13.3）に更新してください。** **VPN・オーバーレイの注意**：Tailscale（`fd7a:115c:a1e0::/48`）・ZeroTier などのオーバーレイや VPN が、私用アドレス（IPv4 の RFC 1918）や ULA（`fc00::/7`）で遠くの相手につながっている場合、egress 遮断はそこへの通信を止めません（その宛先は「ローカル」として通すため）。そうした端末で確実に止めたい場合は `cut_method: full` を使ってください。なお IPv6 のリンクローカル・ULA は、iptables・Windows の経路では通し、nft・pf の経路では止めます（経路で扱いが違います）。

### インストール

```bash
# タグを固定して1行で入れる（推奨・外部レジストリを経由しない）
uv tool install "git+https://github.com/KAMANOI/zee@v0.13.3"

# または、手元で開発する場合
git clone https://github.com/KAMANOI/zee.git
cd zee
pip install -e .
```

> **`pip install zee` / `npx zee` は使わないでください。** PyPI と npm の `zee` は
> 別の作者による無関係なパッケージです（2026-09-05 実測）。Zee はこのリポジトリからのみ
> 配布しています。

### 起動

```bash
# 1. 資産プロファイルを作成
cp examples/assets.example.toml ./assets.toml
# 編集して decoy_paths を自組織のパスに置き換える
# 既定では Zee 専用ディレクトリ（~/.local/share/zee-decoys/）を例示
# ※ ~/Documents や ~/Desktop は避ける：macOS の iCloud「デスクトップと書類」や Windows の OneDrive
#   フォルダー同期が有効だと、おとりと埋め込んだ canary URL がクラウドに複製される

# 2.（任意）macOS / Windows での「読み取り検知」を有効化する
#    自前 webhook 受信器 / Canarytokens.org / AWS Lambda 等の外部
#    エンドポイントを用意し、その URL を環境変数で渡します。
#    未設定でも Zee は動きますが、macOS / Windows での「読むだけ」の
#    攻撃は観測されません（Linux は inotify で直接観察）。
export ZEE_CANARY_BASE_URL="https://your-receiver.example.com/r"

# 3. 復旧トークンを 1 回だけ生成（v0.3 以降必須）
zee init-restore-token   # 表示されたトークンを安全な場所に控える

# 4. 監視開始（既定は dry_run、実遮断なし）
zee watch -c ./assets.toml

# 5. 別ウィンドウで「攻撃者の改ざんを真似て」囮を書き換えてみる
echo "tampered $(date)" >> ~/.local/share/zee-decoys/.env
#  → 変更系の接触（modify）として高信頼イベントを 3 OS 共通で記録します。
#  Linux では `cat <decoy>` のような読み取りだけでも記録します（inotify が
#  open/read を直接観察するため）。
#  macOS / Windows での読み取り検知は、ZEE_CANARY_BASE_URL を設定した
#  ときだけ機能します（決して Zee 本体には戻らず、外部受信器で発火）。

# 6. （遮断が走った後）復旧
zee restore <asset_id> --token <TOKEN>
# または環境変数経由：
ZEE_RESTORE_TOKEN=<TOKEN> zee restore <asset_id>
# 遮断の記録（cut_state.jsonl）が無い・壊れている時は、何も戻さず拒否します（Z605）。
# 状態を確認したうえで、全インターフェースを戻す緊急用：
# zee restore <asset_id> --token <TOKEN> --all-interfaces
```

### このフェーズの Zee がすること／しないこと

**すること**：
- 囮ファイルを設置・登録する
- 囮への接触（OS の検知能力に応じて open / read / modify）を高信頼イベントとして検知する
- ローカル通知＋（任意で）webhook を出す
- `response_mode: auto` の資産では、`dry_run: false` のときのみ自動遮断する
- すべてを計測する（検知レイテンシ・遮断完了時刻・誤検知マーカー）

**しないこと**：
- 侵入そのものの防御（入口防御の役割・置き換えない）
- ヒューリスティック検知での自動遮断（高信頼の囮接触のみ）
- 自動再接続（復旧は手動：`zee restore <asset_id>`）

### 検知能力マトリクス

`zee capability` で出力できます。実装の現在地：

| OS | Backend | open | read | modify | canary fallback | status |
|---|---|---|---|---|---|---|
| Linux | inotify | yes | yes | yes | no | implemented |
| macOS | kqueue [+ canary if `ZEE_CANARY_BASE_URL`] | no | no | yes | yes (when configured) | implemented |
| Windows | ReadDirectoryChangesW [+ canary if `ZEE_CANARY_BASE_URL`] | no | no | yes | yes (when configured) | implemented (Windows 実機未検証) |

- **Linux** — `inotify` で open / read / modify を直接観察します（標準ライブラリのみ・ctypes 経由）。canary は不要です
- **macOS** — `kqueue/EVFILT_VNODE` で変更系を観察。read 検知は OS の制約（Endpoint Security framework が必要）で直接できないため、**`ZEE_CANARY_BASE_URL` を設定すると seeder が囮ファイルに canary URL を埋め込み**、攻撃者がその URL を辿った瞬間に operator が指定した外部エンドポイントで発火します（Zee 本体には戻りません）。`ZEE_CANARY_BASE_URL` 未設定では canary URL は埋め込まれず、macOS デコイへの「読むだけ」の攻撃は観測されません
- **Windows** — `ReadDirectoryChangesW` で親ディレクトリの変更系を観察。read 検知は SACL + Object Access 監査が必要で、v1 では対応外。macOS と同様、**`ZEE_CANARY_BASE_URL` を設定すると read 検知が canary URL 経由で有効化** されます

`ZEE_CANARY_BASE_URL` の選び方（README §canary 受信エンドポイント）：
- **Canarytokens.org**（無料・自動・推奨）
- **自前 webhook 受信器**（Cloudflare Worker / AWS Lambda / Vercel Edge Function 等）
- **Slack / Discord / メール転送**は webhook 受信器の先に operator が組み立てる

macOS では実機で動作を確認しています。テストスイートとスモークテストは CI（Ubuntu / macOS / Windows）で通っています。Linux・Windows の実機での連続稼働の検証は未実施です（詳細は [docs/verification/](./docs/verification/README.md)）。

### 誤検知対策（プロセス allowlist は採用していません・正直に）

現在の Zee の watcher（Linux inotify / macOS kqueue / Windows ReadDirectoryChangesW）は、**囮を触ったプロセスを報告しません**。したがって、プロセス名や exe パスによる allowlist（許可リスト）を検知時に参照する仕組みは入っていません。allowlist 用のデータ構造は将来用に残していますが、現リリースでは responder からは一切呼ばれません。「実装されているのに効かない」ものを既定で同梱すると安心感の誤誘導になるため、既定の allowlist も同梱していません。

代わりに、誤検知は次の 2 つで抑えます。

**1. 配置で抑える（最も効く層）**

囮を、バックアップ・ウイルス対策・OS のファイルインデクサ等の **走査対象から外れた場所に置く**。手順例：

- **macOS Spotlight 除外**：システム設定 → Siri と Spotlight → プライバシー で、囮ファイルを置くフォルダを追加
- **macOS Time Machine 除外**：システム設定 → 一般 → Time Machine → オプション で、囮フォルダを除外
- **Windows 検索インデックス除外**：設定 → 検索 → Windows を検索 → 詳細設定の検索インデクサー → インデックスを作成するパスから外す
- **バックアップソフト除外**：Backblaze / Arq / Restic 等の各設定で囮パスを除外
- **AV/EDR 除外**：Microsoft Defender / CrowdStrike / SentinelOne 等の「スキャン除外」に囮パスを登録（運用ポリシーで許される範囲で）

**2. 自動遮断の発火条件で抑える（仕組みで安全側に倒す層）**

`response_mode: auto` の資産でも、自動遮断が発火するのは **変更系の接触（書き込み・削除・改名・拡張）** だけ です。**読み取り系の接触（open / read / 属性参照）** は通知のみで、自動遮断しません。

理由：正規のバックアップ・AV・インデクサが囮に対して行うのは原則「読み取り」だからです。「変更」は通常行いません。プロセスを特定できなくても、操作の種類だけで「正規ソフトが普通やらない動き」を区別でき、誤検知に対して構造的に安全になります。

通知には毎回ヒントが添えられます：

- 読み取り通知：「正規ソフトの可能性。心当たりがなければ確認し、`zee cut <asset_id>` で手動遮断してください」
- 変更通知：「正規ソフトは通常この操作を行いません。危険度が高い可能性」（auto + dry_run=false なら自動遮断対象）

「正規ソフトなので無視してよい」と断定するヒントは一切出しません。最終判断は人間に委ねます。

**3. 通知に影響の段階表記を付ける（専門の担当者がいない利用者向け）**

通知のタイトルと本文に、4段階（情報／注意／警戒／重大）の影響表記と判定理由1行を付けます。専門知識がなくても、通知を見た瞬間にどれくらい深刻かが分かります。

段階は「触れられたパスの機微性（認証情報・鍵／個人情報を含みうるデータ／一般ファイル）」「その認証情報が及ぶ範囲（資産の種別）」「資産の業務上の広がり（囮の数・共有資産か・夜間も稼働しているか）」の3軸から決めます。パスの実体（ファイル名やディレクトリ名）は通知に出さず、カテゴリ名だけを表示します。

この段階表記は表示だけの機能です。**自動遮断の判定（上記2.）には一切使いません。** 段階表記を取り除いても、遮断するかどうかの動作は変わりません（テストで固定しています）。

なお、プロセス名一致による allowlist を将来採用するには Linux fanotify / macOS Endpoint Security / Windows minifilter 等の特権バックエンドが必要で、MVP の軽量・低権限の方針と合いません。必要になった時点で別途設計します。

---

## 法制度との関係（2026-10-01〜）

2026-10-01、重要電子計算機に対する不正な行為による被害の防止に関する法律（令和7年法律第42号、通称「サイバー対処能力強化法」。[e-Gov](https://laws.e-gov.go.jp/law/507AC0000000042)）と、同法の施行令・報告命令が施行されました。

**Zee は攻撃元の機器への接続・操作（いわゆる無害化）を行いません。法律上その権限もありません。** 攻撃に使われている機器への措置（サイバー危害防止措置）の規定は、警察官を対象とする警察官職務執行法 第6条の2（[e-Gov](https://laws.e-gov.go.jp/law/323AC0000000136)）と、それを自衛官に準用する自衛隊法の規定にあります（後者は同法第61条第2項第8号の記載で確認。自衛隊法の本文は未確認）。民間事業者やツールに同様の権限を与える規定は、確認した範囲にはありません。

Zee が提供するのは従来どおり、端末内での封じ込め（書き込み・削除・リネームの検知と、`response_mode: auto` かつ `dry_run: false` を明示したときだけの自動遮断。既定は dry_run）と、その記録の整備です。`zee export` は、Zee が既に記録した内容を、利用者が選んだ提出先（警察のサイバー犯罪相談窓口、JPCERT/CC、法定の報告義務がある場合はその宛先）に添付しやすい形にまとめるだけのコマンドです。**提出するかどうか、どこに提出するかは利用者が判断してください。Zee は何も送信しません。**

- **報告義務の有無はご自身で確認してください** — 法第5条の報告義務を負うのは、同法第2条第3項の「特別社会基盤事業者」（経済安全保障推進法の特定社会基盤事業者のうち、特定重要電子計算機を使用するもの）です。報告は、事象の発生を認知した後「速やかに」、さらに「認知した日から三十日以内に」所管大臣と内閣総理大臣へ報告書を出す形です（報告命令 第4条第2項・[e-Gov](https://laws.e-gov.go.jp/law/508M60000F5A004)）。報告書の様式は所管大臣と内閣総理大臣が定めるとされており、Zee はその様式を確認できていません。個人や、指定を受けていない事業者には、この条文上の報告義務はありません。Zee は該当するかどうかを判定しません。
- **`zee export --out <prefix>`** — 対象期間（`--since` / `--until`、ISO8601。タイムゾーン省略は UTC、日付のみはその日の 00:00 UTC）の検知イベントと、解除されていない遮断記録を `<prefix>.json`（機械可読）と `<prefix>.txt`（人が読む用）に書き出します。ファイルは所有者だけが読める権限（0600）で新規作成し、同名のファイルやリンクが既にあれば上書きせずに止まります（`--force` で置き換え）。既定でパス情報（`detail`）をマスクします（`--no-redact` で解除）。外部への送信は行いません。MCP の `query_containment_report` も同じ内容を返します（読み取り専用・既定 50 件まで）。
- **`zee incident-report --export-json <prefix>.json --recipient police|ppc --out <prefix2>`** — `zee export` の JSON を読み、警察（`police`）または個人情報保護委員会（`ppc`）への相談・報告に添付する文書を `<prefix2>.json` / `.txt` / `.html`（html はブラウザの印刷で PDF 化できます）に書き出します。本文は選んだ宛先の報告項目に沿って並べ、末尾には警察・PPC 両方の窓口を参考として載せます。窓口の URL・電話番号・受付時間は 2026-10-09 時点の確認結果で、提出前にご自身で公式ページを確認してください。入力ファイルは読むだけで、出力先が入力と同じパスなら `--force` でも上書きしません。`--no-redact` で作った export を渡すと、パスが伏せられないまま報告書に載ります（報告書と標準エラーで注意を出します）。事案の範囲（どの期間・どのファイルを1件として扱うか）は利用者が決めます（Zee は接続元を記録しないため自動でまとめません）。**Zee は何も送信しません。**
- **`asset_id` はマスクされません** — 封じ込め範囲の特定に必要なため、そのまま出力されます。`assets.toml` の `id` に個人名や顧客名を含めないでください。
- **証跡の検証とその限界** — `events.jsonl` / `metrics.jsonl` は書き込み時に各レコードが直前レコードのハッシュを含む形（ハッシュチェーン）で記録され、`zee export` はローテーション済みのファイルも含めて検証します。検知できるのは、途中の行の書き換え・削除・並べ替え、先頭の欠落、ハッシュ付きの行の後に置かれたハッシュなしの行です。**検知できないもの：末尾の行の削除（切り詰め）と、ログを書き換えられる攻撃者による全ハッシュの再計算**（ハッシュは鍵を使わないため）。エクスポートに含まれるイベントには各行のハッシュは入っていません。検証は Zee が端末上で行い、その結果を `chain_verification` に書いています。ログが読めなかった場合は「検証不能」と表示し、終了コード 1 を返します。
- **`export_sha256` が示すのは出力時点以降の同一性だけです** — 出力ファイルとは別の場所（提出メールの本文など）に控えておけば、後からファイルが変わっていないかを照合できます。出力前のログが正しかったことを示すものではありません。
- **法令適合は保証しません** — Zee の出力は、報告命令 第4条第3項の報告事項（7号）のうち第3〜6号の材料の一部にしか対応しません。残りは利用者が記入します。
- 条文の照合結果と、報告事項・Zee の記録項目の対応表は [`docs/containment-report-mapping.md`](./docs/containment-report-mapping.md) にあります。

---

## Limitations — Zee がやらないこと

Zee は誠実に範囲を区切ります。

- **侵入そのものは防がない** — 入口防御（ファイアウォール・EDR・パッチ）の役割を置き換えるものではありません
- **検知中心** — 自動の封じ込め機構は、資産プロファイルで `response_mode: auto` を明示し `dry_run: false` にしたときだけ動きます。既定は dry_run（観測のみ）
- **自動遮断は「変更系の接触」のみ** — open / read / 属性参照 など読み取り系の接触は自動遮断しません。通知で人間に判断材料を渡し、必要なら `zee cut <asset_id>` で手動遮断する設計です。理由：プロセス特定ができない現バックエンドでは、正規ソフト（バックアップ・AV・インデクサ）が普通やらない操作だけを自動遮断の根拠にするのが構造的に安全だからです
- **macOS / Windows の読み取り検知は `ZEE_CANARY_BASE_URL` が設定されているときだけ機能** — kqueue / ReadDirectoryChangesW は読み取り通知を出しません。`ZEE_CANARY_BASE_URL` を設定すると seeder が囮ファイルに canary URL を埋め込み、攻撃者がその URL を辿った瞬間に operator が指定した外部エンドポイントで発火します（Zee 本体には戻りません）。未設定では canary URL は埋め込まれず、macOS / Windows で「読むだけ」の攻撃は観測されません。Linux は inotify が読み取りを直接観察するので canary 不要です
- **プロセス allowlist は現バックエンドでは効かない** — 誤検知制御は許可リストの照合ではなく、「囮を正規ソフトの走査対象外に置く配置ガイド」と「変更系トリガーへの限定」で行います。詳しくは上の「誤検知対策」節
- **`zee restore` には `restore_token` が必要** — v0.3 から、`zee init-restore-token` で生成したトークンを `--token` または `ZEE_RESTORE_TOKEN` 環境変数で渡さないと実行できません。別シェルから誤って遮断を巻き戻す事故は防げますが、`~/.zee/restore_token` は同じユーザーなら読めるため、同じユーザー権限の攻撃者（root 相当でなくても）にはバイパスされます。マルチユーザー本番では `zee restore` を `sudo` で囲うか、専用ユーザーで運用してください
- **イベントログは `decoy_ref`（asset_id#index）で記録** — v0.3 から、events.jsonl には絶対パスではなく `decoy_ref` を書きます。ログを読めた攻撃者が囮の位置を一覧化することはできなくなりました（対応関係は `assets.toml` 経由）
- **限界がある** — 機械の速度で完全自動完結する相手や、ごく小さく具体的な秘密（単一の API キーなど）の保全は、Zee の範囲を超えます。Zee が時間を稼げる対象は「人間〜半自動の侵入後活動」（侵入が成功した後、攻撃者が偵察・横移動・データ持ち出しに進む段階）です
- **検証の範囲** — 入口ゲートの判定ロジックは、合成検体による社内の再現試験とテストスイートで確認しています（自然文の言い換えによる指示すり込みは、未知の検体の盲検試験で検出できていません）。囮・封じ込めは、テストスイートと、隔離した macOS 環境での dry_run の実演（v0.10.1 付近の版で実施）で確認しています。専門家・第三者機関による独立評価は受けていません。実際の遮断（`dry_run: false`）の試験は、GitHub Actions の仮想ランナー（Linux はネットワーク名前空間の中、macOS、Windows は英語版のみ）と macOS 実機1台（MacBookPro17,1／macOS 26.6.2）で行い、いずれも通信が止まって復旧で戻ることを確認しました（2026-10-15）。**範囲：IPv4 は全経路で実測、IPv6 は Linux の名前空間で実測（v0.13.1。macOS・Windows のランナーは IPv6 の外向き経路が無く未測定）／新しい接続のみ（遮断前から開いていた接続は測っていません）／Windows は英語版の仮想ランナーのみで実機なし／Linux も仮想ランナーのみで実機なし／全面遮断（full）は Linux ランナーと macOS 実機1台のみ／macOS 実機では v0.13.0 の規則で、Zee 自身の復旧だけで pf の状態・ネットワークサービスが実行前と同一に戻ることも確認**。手順と結果は [docs/verification/real-cut.md](./docs/verification/real-cut.md)。結果と条件は [docs/verification/](./docs/verification/README.md) にあります。本番運用の前に、ご自身の環境でも確認してください

これは床であって天井ではありません。安全だと言う前に、失敗条件を先に書きました。

---

## みんなで防災 — Defense by everyone, for everyone

Zee は **seed 型 OSS** として運営されます。メンテナはリファレンス実装と設計を公開し、実際にあなたの環境で動かす・OS の更新に追従させる・自分の業種に合わせて改造するのは **各自** がやってください。一人の管理者が全 OS の仕様変更に永続的に追従するモデル（OSS のメンテナ疲れ問題の典型）から最初から外れます。

代わりに、**気付きと修正を共有する場** が用意されています：

| 場所 | 用途 |
|---|---|
| 🔧 [Discussions → Maintenance Q&A](https://github.com/KAMANOI/zee/discussions/categories/q-a) | 「Mac 26.x で動かなくなった → こう直した」「日本語 Windows でこの修正が効いた」 |
| 🌱 [Discussions → Show your fork](https://github.com/KAMANOI/zee/discussions/categories/show-and-tell) | 「うちのサロン / 小規模 EC / 士業はこう使っている」<br />**実例 1 号**：[Zee v0.5 を macOS で 5 分試した記録（dry_run フルサイクル）](https://github.com/KAMANOI/zee/discussions/3) |
| 📚 [Wiki](https://github.com/KAMANOI/zee/wiki) | 安定したナレッジ（OS 別メンテ手順・動作確認済み環境・業種別ガイド） |

**自分の環境で動かなくなったら** [`docs/maintenance/`](./docs/maintenance/) の指示書テンプレを Claude / Cursor / Copilot に渡して修正案を生成し、自分のフォークに適用してください。直し方を Discussions に書き残してくれれば、次に同じ問題に当たった人の作業コストが目安として大きく下がります。

これが「みんなで防災」です。Zee 本体のソースに PR を送らなくても、書き残すだけで貢献になります。業種の例：**美容室 / 小規模 EC / 士業 / 町工場** など、どんな現場の使い方でも歓迎します。

> ⚠️ **Discussions / Wiki に投稿する前に：何を貼って何を伏せるか** は [SECURITY.md → Shared vs. private logs](./SECURITY.md#shared-vs-private-logs-v05) を確認してください。`events.jsonl`・`assets.toml`・`ZEE_WEBHOOK_URL`・`ZEE_CANARY_BASE_URL` などは原則として公開しないことになっています。

> 詳しい運営モデルと参加の流れは [CONTRIBUTING.md](./CONTRIBUTING.md) を参照してください。

---

## v0.2 から v0.3 へのアップグレード

v0.3 で `zee restore` がトークン認証必須になりました。アップグレード後の最初の `zee restore` を実行する前に **一度だけ** 次を実行してください：

```bash
zee init-restore-token
```

表示されたトークンを安全な場所に控えてください。以降の `zee restore` では `--token <TOKEN>` または `ZEE_RESTORE_TOKEN=<TOKEN>` 環境変数を渡します。

また v0.3 から `events.jsonl` の各 trap_event レコードに含まれるパス情報は `decoy_path`（旧）から `decoy_ref`（`<asset_id>#<index>` 形式）に変わりました。下流の解析スクリプトを使っている場合は両キーを受け付けるよう更新してください（移行期間中は v0.2 以前の既存ログに旧キーが残ります）。

詳細は [CHANGELOG.md](./CHANGELOG.md) の [0.3.0] エントリ参照。

---

## セキュリティ

脆弱性を見つけた場合の報告方法・対応の目安・修正版の受け取り方は
[SECURITY.ja.md](./SECURITY.ja.md)（[英語版 SECURITY.md](./SECURITY.md)）を参照してください。

---

## ライセンス

[MIT License](./LICENSE)。このリポジトリにあるものはすべてオープンです。

---

## 論文

設計の数学的な背景：
**Prime survival in affine Collatz dynamics（v20）**
→ https://github.com/KAMANOI/collatz-prime-survival/blob/main/paper/prime_survival_affine_collatz_v20.pdf

---

## 支援

Zee は無料です。もし役に立ったら、GitHub Sponsors からの支援を歓迎します。

---

## 免責

- Zee は現在 **Early Public / Research Project** の段階です
- Zee は **万能ではありません** — 侵入そのものを防ぐものでも、すべての攻撃を検知できるものでもありません
- 機械速度の攻撃能力は進化を続けます。新世代モデルが広く使えるようになる局面では、**Zee 自体の脆弱性チェックとパッチ適用が必要** になります
- Zee は入口防御・修正運用を **置き換えるものではなく、補完する一層** です
