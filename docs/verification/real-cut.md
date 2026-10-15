# 実遮断の確認（dry_run なし）

Zee 自身の遮断と復旧のコード（`cut_egress`・`cut_full`・`zee restore` と同じ処理）で、実際に通信を止め、止まったことと戻ったことを測ります。測り方は同じスクリプト `scripts/real_cut_check.py` です：遮断の前に到達を確認 → 遮断 → 到達できないことを確認 → 復旧 → 到達できることを確認。結果は JSON で残ります。

| 環境 | 方法 | 何を確かめるか |
|---|---|---|
| macOS 実機 | `scripts/verify-real-macos.sh`（下の1行） | egress（pf：`com.apple/zee-egress-cut`）と full（ネットワークサービスの無効化）。終わったあと pf の主ルールセット・pf の有効／無効・ネットワークサービスが元どおりか |
| Linux（GitHub Actions の仮想ランナー） | `.github/workflows/real-cut.yml` の linux ジョブ | ネットワーク名前空間の中で、nft・iptables（nf_tables 版）・iptables（legacy 版）それぞれの egress、full（ip link）。ランナー自体の通信には触れない |
| macOS（GitHub Actions の仮想ランナー） | 同 macos ジョブ | pf の egress（実機の代わりではなく追加） |
| Windows（GitHub Actions の仮想ランナー） | 同 windows ジョブ | netsh advfirewall の egress。到達確認は外部の URL |

## macOS 実機での実行（1行）

リポジトリのフォルダで、次の1行を実行します（管理者のパスワードを聞かれます。スクリプトはパスワードを扱いません）。

```
sudo bash scripts/verify-real-macos.sh
```

- 実行中、数秒ずつ通信が止まります（full ではすべてのネットワークサービスを止めます）。ビデオ会議などは止めてから実行してください。
- 実行前に今の pf の設定とネットワークサービスの状態を `docs/verification/real-macos-<日時>/` に控えます。
- 元に戻す保険が3重にあります。シェル側の2つ（スクリプトの終了時＝異常終了を含む、と90秒の時間切れ）は、Zee のアンカーを空にし、実行前に有効だったネットワークサービスを有効に戻し、実行前に pf が無効だったなら無効に戻します。Python 側の45秒の時間切れは、Zee の通常の復旧（`zee restore` と同じ処理）を行います。
- 結果：`docs/verification/real-macos-<日時>/egress.json`・`full.json`・`summary.json`。

## GitHub Actions での実行

`feat/self-defense-20261015` の枝で、この workflow か測定スクリプトを変更して push した時と、手動実行（workflow_dispatch。既定の枝に入った後）でだけ動きます。main への通常の push や PR では動きません。結果は各ジョブのログとジョブの要約（Summary）に JSON で出ます。

ランナーの通信を止めない工夫：Linux は名前空間の中だけで遮断します。macOS は pf の状態表により既存の接続（ランナーと GitHub の接続）は遮断中も通り、新しい接続だけが止まる想定です。遮断は数秒で、Python 側の45秒の時間切れに加え、macOS は2分後に Zee のアンカーを空にするタイマー、Windows は3分後に Zee の規則を消す SYSTEM のタスクを、遮断の前に仕掛けます。Windows で既存の接続が保たれるかは、実行結果で確かめます。

## 実測の結果

| 日付 | 対象 commit | 環境 | 方法 | 止まった | 戻った | Zee 自身の読み直し |
|---|---|---|---|---|---|---|
| 2026-10-15 | 238fb0e（run 38738827699） | Windows ランナー | egress | **いいえ** | — | FAILED（netsh が規則を受け付けず。修正前の不具合） |
| 2026-10-15 | e226127（run 38739379077） | Linux ランナー・名前空間（nft） | egress / full | はい / はい | はい / はい | confirmed / confirmed |
| 2026-10-15 | 同上 | Linux ランナー・名前空間（iptables nf_tables 版） | egress | はい | はい | confirmed |
| 2026-10-15 | 同上 | Linux ランナー・名前空間（iptables legacy 版） | egress | はい | はい | confirmed |
| 2026-10-15 | 同上 | macOS ランナー（pf、`com.apple/zee-egress-cut`） | egress | はい | はい | confirmed |
| 2026-10-15 | 同上 | Windows ランナー（netsh） | egress | はい | はい | confirmed |
| 2026-10-15 | 1c79265（MacBookPro17,1・macOS 26.6.2・`real-macos-20261015-221822/`） | macOS 実機 | egress / full | はい / はい | はい / はい | 成功 / 成功（実行後の pf 主ルールセット・pf 無効状態・ネットワークサービスは実行前と同一） |

ランナーは GitHub が用意する仮想マシンで、実機ではありません。Windows・macOS の full 遮断（全インターフェースの停止）はランナーの接続を失うため行っていません。
