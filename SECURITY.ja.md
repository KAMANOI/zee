# セキュリティ方針（日本語版）

> これは [SECURITY.md](./SECURITY.md)（英語版）と同じ内容の日本語訳です。**食い違いがあれば英語版 SECURITY.md を正とします。** 用語には短い言い換えを添えています。

## 脆弱性を見つけたら（報告の方法）

Zee は「研究・公開初期段階のプロジェクト」ですが、セキュリティを扱うプロジェクトです。
コード・ドキュメント・想定している攻撃シナリオ（脅威モデル）・あるいは Zee の悪用方法に
**脆弱性**（セキュリティ上の欠陥。攻撃者に利用されうる不具合）を見つけた場合は、
**公開の場所（Issues・Discussions・SNS 等）には書かず、非公開で**ご連絡ください。

**推奨：GitHub Security Advisories**（GitHub が用意している非公開の報告専用フォーム）
→ https://github.com/KAMANOI/zee/security/advisories/new

ここから報告すると、報告者とメンテナー（Hiroki Kamanoi）だけが見える非公開のやり取りが始まり、
公開前に内容を整理できます。

**代替手段：** Security Advisories が使えない場合は、Hiroki Kamanoi 宛のメール
（`hirokikamanoi@gmail.com`）に、件名の先頭に `[zee-security]` を付けてご連絡ください。

## 報告に含めてほしいこと

- 問題の内容と、なぜ問題なのかの説明。
- できるだけ小さく再現できる手順（実行したコマンド・ファイルパス・期待した動作と実際の動作）。
- 確認したバージョン／コミットハッシュ（Git の変更履歴の識別子）。
- （任意）修正方法や緩和策の案。

## 報告後に起きること

- **7日以内**に受領の連絡をします。
- **14日以内**に初期判定（受理する／しない／追加情報が必要）を連絡します。
- 受領から**90日**を目標に、協調して公開する日を決めます（修正が先にできて、
  報告者と合意できればそれより早く公開することもあります）。

## 対象範囲

- `src/zee/` と `tests/` 配下の Zee 本体のコード。
- MVP（最小限の実装）の動作（watcher・responder・recovery・notifier・telemetry の各モジュール）。
- 囮ファイル（デコイ）のテンプレートと、その前提にしている脅威モデル。
- 公開しているドキュメント（README・ARCHITECTURE・STARTER_GUIDE・RESEARCH）。

## 対象外

- 利用しているライブラリ・ソフトウェア本体（Python 言語自体・OS）の脆弱性。
  これらはそれぞれの開発元に報告してください。
  （Zee はサードパーティの実行時依存ライブラリを持たず、TOML の読み込みも
  標準ライブラリの `tomllib` を使っています。）
- 利用者側の環境設定ミス（許可リスト・資産プロファイル・Webhook URL の選び方など）。
- Zee が「できない」と明記している範囲についての指摘（Zee は侵入そのものを防ぎません。
  これを指摘すること自体は脆弱性ではなく、最初から正直に書いている設計上の限界です）。

## セーフハーバー（善意の調査者を守る約束）

このポリシーに従った善意のセキュリティ調査について、メンテナーは法的措置を取りません。
調査する側にお願いしたいこと：

- 自分のものではないシステムに対して、プライバシー侵害や破壊的なテストを行わないこと。
- 公開前に、対応のための合理的な時間を確保してもらうこと。
- 見つけた脆弱性を、問題を示すために必要な範囲を超えてデータへアクセスする目的に使わないこと。

## 共有してよいもの・いけないもの

Zee は「種をまかれたオープンソース」として動いており（[CONTRIBUTING.md](./CONTRIBUTING.md) 参照）、
GitHub Discussions や Wiki でメンテナンスの知見を共有することを歓迎しています。
何を貼ってよく、何を伏せるべきかを以下にまとめます。

| 対象物 | 保存場所 | 共有してよいか |
|---|---|---|
| 検知ログ（`events.jsonl`・`metrics.jsonl`） | `~/.local/state/zee/`（0600＝自分だけが読み書きできる権限） | **共有しない。** v0.3 以降はファイルパス（`decoy_path`）を記録しておらず、残る識別子（`decoy_ref`、`asset_id#index`形式）自体はファイル配置を漏らしませんが、記録そのものには自分の資産に対する攻撃者の挙動が残ります |
| 囮トークンの登録簿（`canary_tokens.jsonl`） | `~/.local/state/zee/`（0600） | **共有しない。** 運用者が管理する URL に紐づくトークン ID が含まれます |
| 遮断状態の記録（`cut_state.jsonl`） | `~/.local/state/zee/`（0600） | **共有しない。** Zee が無効化したネットワークインターフェース名・サービス名・ルール名の一覧です |
| 復旧トークン（`~/.zee/restore_token`） | （0600） | **共有しない。** これは秘密情報（パスワードに相当するもの）です |
| **資産プロファイル（`assets.toml`）** | 運用者の作業ディレクトリ | **そのままでは共有しない。** 囮ファイルの場所（ファイルパス）・ネットワークインターフェース名・遮断方法は運用者固有の情報です。サンプルとして共有する場合は `decoy_paths` と `id` を無害な名前に書き換えてください |
| **`ZEE_WEBHOOK_URL`（環境変数）** | シェルの設定ファイル／起動スクリプト | **共有しない。** 自分の Webhook 受信先であり、認証用の文字列を含むことが多いです |
| **`ZEE_CANARY_BASE_URL`（環境変数）** | シェルの設定ファイル／起動スクリプト | **共有しない。** 運用者が管理する外部の受信先と、攻撃者がアクセスしうる URL の形が分かってしまいます |
| リファレンス実装のソースコード | `src/zee/`・`tests/`・`docs/` | **自由に共有可。** MIT ライセンスで公開しており、それ自体がこのプロジェクトの目的です |
| メンテナンスの記録 | GitHub Discussions・Wiki | **ぜひ共有してください。** OS バージョン・言語設定・伏せ字にしたエラーメッセージ・伏せ字にした差分・「何で直ったか」など |
| 業種別の運用メモ | GitHub Discussions・Wiki | **自由に共有可。** 匿名化した業種・囮ディレクトリの形（例：`~/.local/share/zee-decoys/<files>`）・Webhook 受信先の選び方（Canarytokens.org／自前サーバー／AWS Lambda など） |

**Discussions への投稿や、AI との会話に貼り付ける前に**、
[docs/maintenance/README.md](./docs/maintenance/README.md#-before-you-paste-anything-anywhere--read-this)
にある伏せ字チェックリストを一度通してください。

Zee 自体が検知ログをどこかへ自動送信することはありません。Discussions・Wiki への共有は、
次に同じ問題にあたる人のために役立てたい部分だけを、利用者自身が手動で選ぶ行為です。

## 正直な制約（現在のリリースについて）

これらは「未解決のバグ」ではありません。v0.1／v0.2 にあった「既知の限界」節の項目は
v0.3 で解消済みです。以下は、現時点の Zee が「できること」と「できないこと」の境界を、
隠さずに書いたものです。

- **macOS／Windows での「読み取り検知」には、運用者が外部の受信先（`ZEE_CANARY_BASE_URL`）
  を設定する必要があります。**（Canarytokens.org・自前の Webhook・AWS Lambda など、
  自分で用意した受信サーバー）。設定しない場合、囮ファイルに URL が埋め込まれず、
  macOS／Windows での読み取りだけの接触は検知されません（既定で安全側に倒す設計です。
  Linux は `inotify`（OS のファイル監視機能）が読み取りを直接報告するため、受信先の設定は不要です）。
- **読むだけの侵入は、自動では切りません。** `response_mode: auto` かつ `dry_run: false` に
  していても、自動遮断が走るのは囮への「変更系」の接触（書き換え・削除・改名・拡張）だけです。
  「読み取り系」の接触（open／read／属性参照）は通知のみのため、読むだけの偵察や
  認証情報の収集は Zee では止まりません。通知を人が読み、必要なら `zee cut <asset_id>` で
  手動遮断してください。
- **`restore_token` は、root 権限相当の攻撃者を止められません。**
  `~/.zee/restore_token` は POSIX 環境（Linux・macOS）では 0600（本人だけが読み書き可能）
  ですが、同じユーザー権限でシェルにアクセスできる攻撃者はこのファイルを読めてしまいます。
  このトークンが防ぐのは、別のシェルからの事故的な復旧操作と、root権限までは持たない
  通りすがりの攻撃者による復旧です（同じユーザー権限を持つ本気の攻撃者は上記の通り防げません）。
  複数ユーザーが使う本番環境では、`zee restore` を `sudo` 経由にするか、
  専用ユーザーで Zee を動かしてください。`restore_token` は OS レベルのアクセス制御を
  補うものであり、置き換えるものではありません。
- **同じユーザー権限の攻撃者は、今も Zee を止められます。** `zee watch`・遮断の処理・
  `assets.toml`・遮断の記録（cut_state.jsonl）は、どれも利用者本人のユーザーで動く／置かれています。
  そのユーザーのシェルを持つ攻撃者は、監視を止める・設定を書き換える・記録を消すことができます。
  記録を消すだけでは通信は広く戻りません：`zee restore` は形の正しい遮断の記録が無いと拒否し（Z605）、
  全面復旧には `--all-interfaces` の指定が要ります。ただし同じ攻撃者は復旧トークンも読めるため、
  どちらの復旧も自分で実行できます。遮断部を別ユーザーに分ける構成は
  設計済み（[docs/design/self-defense.md](./docs/design/self-defense.md)）ですが、まだ適用していません。
- **Windows では POSIX の権限チェックを行いません。** NTFS（Windows のファイルシステム）は
  POSIX のパーミッションビットではなく ACL（アクセス制御リスト）を使うため、
  `os.stat().st_mode` は実際の ACL に関わらず `0666` を返します。そのため Zee は
  win32 ではグループ／他ユーザーの読み取り拒否を強制しません。Windows での実質的な保護は、
  OS が `%USERPROFILE%\.zee` に既定で適用する ACL です。共有の Windows プロファイルで
  運用する場合は、その ACL を確認してください。
- **Windows 実機でのメンテナーによる手動確認はまだ行っていません。** Windows 用の
  watcher・cut／restore の処理は実装済みで、GitHub Actions のテスト行列
  （[test.yml](.github/workflows/test.yml)）により `windows-latest` 上で
  Python 3.11／3.12／3.13 ごとに、pytest・CLI の動作確認（`zee --version`・
  `zee capability`・`zee init-restore-token`）・PowerShell／netsh の出力解析テストを
  毎回の push で実行しています。日本語／ドイツ語／フランス語版 Windows での継続的な
  動作確認はまだです（CI のランナーは英語版 Windows です）。
- **`cut_egress`（ネットワーク遮断）が通すものは経路で違います。** IPv4：どの経路も
  `10.0.0.0/8`・`172.16.0.0/12`・`192.168.0.0/16` とループバック（`lo`／`lo0`、
  Windows では `127.0.0.0/8`）を通し、IPv4 リンクローカル（`169.254.0.0/16`）は止めます。
  IPv6：`iptables` の経路（ip6tables）と Windows の `netsh` の規則は、ループバック・
  リンクローカル（`fe80::/10`）・ULA（`fc00::/7`）・リンク内マルチキャスト
  （`ff02::/16`。近隣探索に使う）を通します。`nftables` と `pfctl` の経路が通す IPv6 は
  ループバックだけです。APIPA アドレスや、nft・pf の端末で IPv6 のリンクローカル／ULA の
  LAN を使っている場合は、`cut_egress` を有効にする前に遮断ルールを確認してください。
- **私用アドレス・ULA を使う VPN・オーバーレイは、egress 遮断では止まりません。**
  Tailscale（`fd7a:115c:a1e0::/48`）・ZeroTier などのオーバーレイや、RFC 1918 の範囲を
  流す IPv4 の VPN が、私用アドレスや ULA で遠くの相手につながっている場合、その宛先は
  「ローカル」として通るため、そこから持ち出せます。そうした端末では `cut_method: full` を
  使ってください。経路による違いもあります：IPv6 のリンクローカル・ULA は iptables・
  Windows の経路では通し、nft・pf の経路では止めます。
- **IPv6 の外向き通信（v0.13.1 で修正）。** v0.13.0 までは `iptables` の経路（`nft` の
  無い Linux）と Windows の `netsh` の規則が IPv4 だけを対象にしており、IPv6 の外向き
  通信は止まりませんでした。v0.13.1 から `iptables` の経路は同じバックエンドの ip6tables
  にも同じ規則を入れ（そのような ip6tables が無い・コマンドが失敗した時は遮断を FAILED に
  する。IPv4 だけの成功とは言わない）、Windows の規則にも IPv6 の範囲を足しました。
  Linux（ネットワーク名前空間。nft・iptables nf_tables 版・legacy 版）で実測済みです。
  **Windows で IPv6 の通信が止まることは未確認です**（ランナーに IPv6 の外向き経路が
  無いため。規則が入り、読み直しで一致することは確認）。カーネルで IPv6 を無効にした
  Linux（`ipv6.disable=1`）では、iptables の遮断は IPv6 の規則を入れず、結果にそう
  書きます（「IPv6 is disabled in the kernel」）。復旧は ip6tables の「Address family not
  supported by protocol」という応答を「IPv6 のチェーンは無い」と扱います。どちらも
  独立した2つの根拠を要求します：IPv6 のソケットが開けない（EAFNOSUPPORT）**かつ**
  カーネル自身の設定値が IPv6 無効を示す（`/sys/module/ipv6/parameters/disable` が 1。
  読めない・無い時は「確かめられない」扱い）。IPv6 のソケットだけを
  禁じられたプロセス（systemd の `RestrictAddressFamilies` など）は同じエラーを受けますが、
  端末の他の通信は IPv6 で出られるため、その場合の遮断は FAILED、復旧は未確認（Z606）です。
- **macOS・Windows の外向き遮断が止めるのは新しい接続です。遮断の前から開いていた
  接続は続く場合があります。** pf は状態表に載った接続のパケットを新しい規則で
  評価し直さず、Windows ファイアウォールも接続を張る時に規則を当てます。Linux の
  外向き遮断の規則は状態の例外を持たないため、開いている接続も止まります。
  問題になる場合は `cut_method: full` を使ってください。実遮断の試験は新しい接続だけを
  測っています。
- **macOS の外向き遮断の読み直しが見るもの・見ないもの。** Zee の規則（すべて quick
  付き）は `com.apple/zee-egress-cut` に入ります。主ルールセットから条件なしで参照され、
  その前に別のアンカーや `pass ... quick` が無く、`com.apple/` の下の他のアンカーに
  受信専用でない `pass ... quick` や入れ子のアンカーが無い時だけ成功とします（1階層を
  読み、読めなければ未確認＝失敗）。確認の後に足された規則は見張っていません。
- **イベントログは既定では上限なく増え続けます。長期運用では手動でローテーション
  （古いログを別ファイルに移す作業）を計画してください。** `events.jsonl` と
  `metrics.jsonl` は、検知イベントと処理時間の記録をすべて蓄積します。
  10MB を超えると次回書き込み時に自動でローテーション（`<ファイル名>.rNNNNNN_YYYYMMDD_HHMMSS`
  という名前に変えて新しいログを開始）しますが、ローテーションされた古いファイルは
  証拠として永久に保持され、自動削除はされません（Zee 0.10.x 以前は
  `<ファイル名>.YYYYMMDD_HHMMSS` という命名でしたが、これも読み込み対応しています）。
  イベント量が多くなる運用では、手動でのアーカイブ計画も立ててください。

## 脆弱性の協調的開示とは

「協調的開示（Coordinated Disclosure）」は、脆弱性を見つけた人と開発者が協力して、
修正してから公表するという進め方です。GitHub 公式ドキュメント
「[Coordinated disclosure of security vulnerabilities](https://docs.github.com/en/code-security/concepts/vulnerability-reporting-and-management/coordinated-disclosure)」
の要点を、Zee を使う方向けに次の3行にまとめます。

- 脆弱性を見つけたら、公開の場（Issues・Discussions・SNS）に書かず、まず非公開で知らせる。
- 修正版が公開されてから、詳しい内容を公表する（連絡が取れない・対応が極端に遅い場合を除く。
  目安は上の「報告後に起きること」にある**90日**の開示目標）。
- Zee では、Security タブの **「Report a vulnerability」** が非公開の報告窓口です
  （上の「脆弱性を見つけたら」節と同じ窓口）。

> 出典：[GitHub Docs「Coordinated disclosure of security vulnerabilities」](https://docs.github.com/en/code-security/concepts/vulnerability-reporting-and-management/coordinated-disclosure)（[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)）。
> 上記3行は原文の全訳ではなく、Zee 利用者向けに要点を抜き出して要約・翻案したものです。

## 修正版の受け取り方

Zee は `uv tool install` でタグ（バージョンの目印）を固定して導入する方式のため、
PyPI／npm のような配布サイト経由の自動アラートは届きません
（そもそも PyPI／npm の `zee` は別人の無関係なパッケージです）。
代わりに、GitHub のリポジトリ画面から通知を受け取る設定をしてください。

1. リポジトリ画面（https://github.com/KAMANOI/zee ）右上の **Watch** を開く。
2. **Custom** を選び、**Releases**（新しいバージョンの公開）と
   **Security alerts**（セキュリティに関する警告）にチェックを入れて保存する。
3. 新しいバージョンが出たら、README の導入手順と同じ形式で入れ替える：

```bash
# <新しいタグ> は公開された新しいバージョン番号に置き換える
uv tool install --force "git+https://github.com/KAMANOI/zee@<新しいタグ>"
```

## 脆弱性修正の記載方法

脆弱性を修正したリリースは、[CHANGELOG.md](./CHANGELOG.md) とリリースノートに
「Security」区分を設けて明記します。
