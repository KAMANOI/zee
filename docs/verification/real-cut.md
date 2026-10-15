# 実遮断の確認（dry_run なし）

Zee 自身の遮断と復旧のコード（`cut_egress`・`cut_full`・`zee restore` と同じ処理）で、実際に通信を止め、止まったことと戻ったことを測ります。測り方は同じスクリプト `scripts/real_cut_check.py` です：遮断の前に到達を確認 → 遮断 → 到達できないことを確認 → 復旧 → 到達できることを確認。結果は JSON で残ります。**合格は、Zee の遮断と通常の復旧がどちらも成功を返し（復旧は安全タイマーではなく通常の経路）、かつ通信が止まって戻った時だけ**です（v0.13.0 から。それまでは到達の変化だけで合格にしていました）。

| 環境 | 方法 | 何を確かめるか |
|---|---|---|
| macOS 実機 | `scripts/verify-real-macos.sh`（下の1行） | egress（pf：`com.apple/zee-egress-cut`）と full（ネットワークサービスの無効化）。pf の有効／無効・主ルールセット・ネットワークサービス・Zee のアンカーが元どおりかを、**Zee の復旧の直後**と**スクリプトの後始末の後**の2回比べる |
| Linux（GitHub Actions の仮想ランナー） | `.github/workflows/real-cut.yml` の linux ジョブ | ネットワーク名前空間の中で、nft・iptables（nf_tables 版）・iptables（legacy 版）それぞれの egress、full（ip link）。ランナー自体の通信には触れない |
| macOS（GitHub Actions の仮想ランナー） | 同 macos ジョブ | pf の egress（実機の代わりではなく追加）。Zee の復旧の後に pf の有効／無効が遮断前と同じか |
| Windows（GitHub Actions の仮想ランナー） | 同 windows ジョブ | netsh advfirewall の egress。到達確認は外部の URL |

## macOS 実機での実行（1行）

リポジトリのフォルダで、次の1行を実行します（管理者のパスワードを聞かれます。スクリプトはパスワードを扱いません）。

```
sudo bash scripts/verify-real-macos.sh
```

- 実行中、数秒ずつ通信が止まります（full ではすべてのネットワークサービスを止めます）。ビデオ会議などは止めてから実行してください。
- 実行前に今の pf の設定とネットワークサービスの状態を `docs/verification/real-macos-<日時>/` に控えます。どれかが読めない・形がおかしい時、Zee のアンカーに既に規則がある時（Zee の遮断が効いている最中）、出力先がシンボリックリンクの時は、**何も遮断せずに中止**します。root で作業ツリーのコード（`.venv`・`src/`）を動かすので、自分だけが書き換えられる作業ツリーでだけ実行してください。
- 元に戻す保険が3重にあります。シェル側の2つ（スクリプトの終了時＝異常終了や Ctrl-C を含む、と180秒の時間切れ）は、Zee のアンカーを空にし、実行前に有効だったネットワークサービスを有効に戻し、実行前に pf が無効だったなら無効に戻します。Python 側の45秒の時間切れは、Zee の通常の復旧（`zee restore` と同じ処理）を行います。
- **「元どおり」の判定は2回**：Zee の復旧の直後（スクリプトが何も戻す前）と、スクリプトの後始末の後。どちらかが実行前と違えば終了コードは1です。
- 結果：`docs/verification/real-macos-<日時>/egress.json`・`full.json`・`summary.json`。

## GitHub Actions での実行

main（と `feat/self-defense-20261015` の枝）への push のうち、遮断・復旧のコード（`src/zee/responder/`・`src/zee/recovery/`）、この workflow、測定スクリプトのどれかを変えたものと、手動実行（workflow_dispatch）で動きます。PR では動きません（他人の PR がランナーのファイアウォールを変えられないように）。結果は各ジョブのログとジョブの要約（Summary）に JSON で出ます。

ランナーの通信を止めない工夫：Linux は名前空間の中だけで遮断します。macOS は pf の状態表により既存の接続（ランナーと GitHub の接続）は遮断中も通り、新しい接続だけが止まる想定です。遮断は数秒で、Python 側の45秒の時間切れに加え、macOS は2分後に Zee のアンカーを空にするタイマー、Windows は3分後に Zee の規則を消す SYSTEM のタスクを、遮断の前に仕掛けます（タスクが作れない・中身が読めない時は遮断しません。タスクは Zee の規則が消えたと確認できた時だけ消し、残っていればタスクを残して失敗にします）。**既存の接続が遮断中も通ること自体が、macOS・Windows の egress の限界です**（pf の状態表・Windows ファイアウォールは接続を張る時に規則を当てる）。この試験は新しい接続だけを測っています。

## 実測の結果

| 日付 | 対象 commit | 環境 | 方法 | 止まった | 戻った | Zee 自身の読み直し |
|---|---|---|---|---|---|---|
| 2026-10-15 | 238fb0e（run 38738827699） | Windows ランナー | egress | **いいえ** | — | FAILED（netsh が規則を受け付けず。修正前の不具合） |
| 2026-10-15 | e226127（run 38739379077） | Linux ランナー・名前空間（nft） | egress / full | はい / はい | はい / はい | confirmed / confirmed |
| 2026-10-15 | 同上 | Linux ランナー・名前空間（iptables nf_tables 版） | egress | はい | はい | confirmed |
| 2026-10-15 | 同上 | Linux ランナー・名前空間（iptables legacy 版） | egress | はい | はい | confirmed |
| 2026-10-15 | 同上 | macOS ランナー（pf、`com.apple/zee-egress-cut`） | egress | はい | はい | confirmed |
| 2026-10-15 | 同上 | Windows ランナー（netsh） | egress | はい | はい | confirmed |
| 2026-10-15 | 1c79265（MacBookPro17,1・macOS 26.6.2・`real-macos-20261015-221822/`） | macOS 実機 | egress / full | はい / はい | はい / はい | 成功 / 成功（下の注） |
| 2026-10-15 | 7c70c9d＝v0.13.0（同じ Mac・`real-macos-20261015-233822/`） | macOS 実機 | egress / full | はい / はい | はい / はい | 成功 / 成功。**Zee の復旧の直後**の時点で pf の状態（Disabled）・主ルールセット・ネットワークサービスが実行前と同一、Zee のアンカーは空。スクリプトの後始末の後も同一 |
| 2026-10-15 | dcd2b18（run 38748098000）・ae7d8f0（run 38750135590）・9aca195（run 38751054337）・34c08d2（run 38751541014、再レビュー3回目の修正後）。いずれも全ジョブ合格・v0.13.0 の修正後。合格＝Zee の遮断と通常の復旧がどちらも成功＋止まって戻った） | Linux ランナー・名前空間（nft） | egress / full | はい / はい | はい / はい | confirmed / confirmed |
| 2026-10-15 | 同上 | Linux ランナー・名前空間（iptables nf_tables 版・legacy 版） | egress | はい | はい | confirmed（復旧は iptables・iptables-legacy・iptables-nft をそれぞれ読み直して不存在を確認） |
| 2026-10-15 | 同上 | macOS ランナー（pf、quick 付きの規則・`pfctl -E`） | egress | はい | はい | confirmed（復旧の `pfctl -X` で、遮断前に無効だった pf が Zee の復旧だけで無効に戻った） |
| 2026-10-15 | 同上 | Windows ランナー（netsh、en-US） | egress | はい | はい | confirmed |

**実機の行の注（「元どおり」は誰が戻したか）**：この回（commit 1c79265）は、実行後の pf 主ルールセット・pf の無効状態・ネットワークサービスが実行前と同一でしたが、比較の前にスクリプトの後始末（Zee のアンカーを空にする・実行前に有効だったサービスを有効にする・`pfctl -d`）が走っていました。**pf を無効に戻したのはスクリプトで、Zee 自身ではありません**（当時の Zee は `pfctl -e` で有効にし、復旧で無効に戻していませんでした）。サービスについても、Zee の復旧で戻ったのかスクリプトで戻ったのかは、この回の記録では区別できません（Zee の復旧自体は成功を返しています）。v0.13.0 では、Zee の復旧が `pfctl -X` で自分の有効化の参照だけを返し、スクリプトは Zee の復旧の直後とスクリプトの後始末の後を分けて比べます。v0.13.0 の規則（quick 付き・`pfctl -E`／`-X`）は、公開後に同じ実機で流し直しました（下の表の 7c70c9d の行）。

ランナーは GitHub が用意する仮想マシンで、実機ではありません。Windows・macOS の full 遮断（全インターフェースの停止）はランナーの接続を失うため行っていません。
