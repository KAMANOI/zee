# 設計案：Zee の自己防衛 — 攻撃者が Zee を止めようとしても、遮断部まで止まらないようにする

状態：設計案＋第一段の実装（枝 `feat/self-defense-20261015`、main 726a431 から分岐）。**push・リリースはしていない。**
作成：2026-10-15
元の指示書：2026-10-15「Zee 自己防衛：遮断部の権限分離と改ざん耐性」（非公開）

> 「確認済み」は作者がこのリポジトリと開発機（macOS）で実際に見たもの。「未検証」は見ていないもの。
> 権限分離を実際に適用する手順（root デーモン化・専用ユーザー作成・pf の有効化）は **代表の承認が要る** ので、
> この文書では §7 に手順案として書くだけにとどめ、実行していない。

## 0. 目標（指示書の言葉のまま）

侵入者が Zee の仕組みを知っていても、業務環境を侵害した権限だけでは、Zee の設定変更・停止・遮断解除まで行えない。
防御機能が失われた場合も、正常に動いているようには見せない。

「Zee を隠す」のではなく、「Zee を知っていても、止める権限は渡っていない」構成にする。

## 1. 前提の照合（指示書 と main 726a431）

指示書の本人も「公開版の資料と一部の処理を確認した範囲」と書いている。手元の main と照らした結果。

| 指示書の前提 | main の実際（確認済み） | 判定 |
|---|---|---|
| watcher / policy / responder の権限分離は将来フェーズ | `ARCHITECTURE.md`「設計意図として将来フェーズに引き継ぐもの」に明記。全部が一つのプロセス・同じユーザーで動く（`cli._cmd_watch` が watcher を起こし、同じプロセスの `sequence.handle` が `cut_full` / `cut_egress` を直接呼ぶ） | 一致 |
| 復旧トークンは同じユーザーのシェルを持つ攻撃者にも読める | `SECURITY.md` Honesty boundaries に明記。`~/.zee/restore_token`（0600） | 一致 |
| `restore.py` は遮断記録が無いと広く通信を有効化する旧方式に戻る | 一致。さらに、互換処理3関数（Linux・macOS・Windows）は**個々の OS コマンドの成否を見ずに常に成功を返していた**。その結果「Zee restored」と通知し、記録を解決済みにする | 一致（指示書より悪い） |
| 遮断台帳は同じユーザーが書ける | `~/.local/state/zee/cut_state.jsonl`（0600・本人所有）。記録を消すだけで上の旧方式に入れた | 一致 |
| ログは鍵なしハッシュチェーンで、再計算・末尾切り詰めを防げない | README の `zee export` の説明に明記（SECURITY.md ではない）。端末外への固定は無い | 一致（出典は README） |
| 自動遮断の ON/OFF・設定保護は無い | **半分ある。** `src/zee/responder/permission.py`（ON/OFF の記録・0600/0700・原子的書き込み・ホストロック）が main に入っているが、**意図的に未配線**（commit 97be50e「unwired」）。`handle()` は `decide()` を呼ばない | 食い違い（本件では配線しない。§6） |
| 「認証済みの管理経路」は新しく作る | **部品が既にある。** `src/zee/egress/`（持ち出し承認）が、別端末の ES256 署名・公開鍵登録簿・設定変更（`CONFIG_OPS`：allow/protect/key の追加削除・disable）の署名必須化を実装済み。ただしこちらも未配線 | 食い違い（§4.3 で共通化する） |
| 遮断が失敗しても成功に見える（指示書2章） | 本文の想定以上に具体的に存在した：①遮断が失敗しても通知の題名が「Zee cut applied」②インターフェースが0件のとき遮断「成功」③複数インターフェースの一部だけ落ちたとき、落ちた分も記録しない（→次の restore が旧方式へ） | 一致（具体的な穴3つ） |
| 死活は監視対象の自己申告に頼っている | 死活確認は `permission.watch_running()` がロックファイルを掴めるかを見るだけ＝「プロセスがある」しか分からない。イベント処理が進んでいるかは見ていない | 一致 |
| IPv6 の遮断漏れ | main は IPv4 のみ。別の枝 `fix/egress-ipv6` で対応中 | 本件では触らない |

**10/7 の GPT コードレビューとの重複**：`20261007-0911` の報告どおり、第2回以降は再現テスト（別の作業ツリーにある未コミットのファイル `tests/test_gpt_repro_sections_2_to_5.py`、xfail）までで止まっている。その §3a（失敗でも applied）・§3b（0件で成功）・§4a（一部成功を記録しない）・§4b（記録の無い資産の restore が全体を戻す）は本件と同じ穴で、**本件の第一段でまとめて直した**。再現ファイル自体は別の作業ツリーにあるため本枝には持ち込まず、同じ内容を `tests/test_self_defense.py` に書き直した（あちらの xfail は、この枝を取り込むと XPASS になり、strict なので外す必要がある）。

## 2. 何から守るか（段階）

| 段階 | 攻撃者が持つ権限 | この設計の答え |
|---|---|---|
| A | 業務アプリ・業務ユーザー（Zee を動かしているのと同じユーザー） | **遮断部と設定・台帳・復旧を別ユーザー（root 所有）に移す**。業務ユーザーからは書けない・止められない（§3・§7） |
| B | ホストの管理者（root / Administrator） | 端末の中では守れない。ファイル権限は迂回され、プロセスへのシグナルも送れる。**端末外の機器（ゲートウェイ）から遮断できるようにし、その解除の資格情報を端末に置かない**（§5、第三段） |

段階 A を固めるのが第一段・第二段。段階 B は第三段。最初から独自カーネルドライバーや OS ごとの強い自己保護（Windows の ELAM 等）は作らない。

## 3. 構成：権限を分けた最小の遮断部

```
業務ユーザー（侵害されうる）
  zee watch：囮の観察・通知・AI 判定・囮生成
        │  遮断要求（3項目だけ：asset_id / op_class / confidence）
        │  Unix ドメインソケット（遮断部ユーザーが所有・業務ユーザーは書き込みのみ）
        ▼
遮断部（専用ユーザー＋遮断に必要な最小の root 権限）
  1. 要求元の確認：ソケットの相手の uid が登録された watch ユーザーか（OS が教える値。自己申告ではない）
  2. 要求の検証：決められた形以外は拒否（responder/blocker.py の refusal と同じ規則）
  3. 方針の確認：root 所有の assets.toml・自動遮断の許可（permission）から、資産と遮断方法を自分で決める
  4. 遮断：cut_full / cut_egress だけを実行。台帳は遮断部だけが書ける場所へ
  5. 結果の確認：OS の状態を読み直して、本当に止まったかを記録
        ▼
OS の通信遮断（pf / nftables / netsh）
```

遮断部に**持たせないもの**：文章の解釈、AI 判定、囮の生成、任意のコマンド実行、一般のファイル編集、ネットワーク送信。
業務側からは**できないようにするもの**：遮断方針の変更、自動遮断の OFF、復旧、台帳の書き換え、遮断部の停止。

要点：
- **要求者は遮断方法も対象も選べない。** 要求に入るのは「どの資産で・何が起きたか」の事実だけ。方法は遮断部が自分の保持する方針から決める。侵害された watch が偽の要求を出しても、できるのは「方針どおりの遮断」だけで、解除・別の対象への操作は形として表現できない。
- **偽の要求で遮断を起こされる可能性は残る**（watch を乗っ取った攻撃者は「change が起きた」と嘘をつける）。これは「止められない」の逆向きの被害＝業務停止で、利用者が自動遮断を許可した範囲に限られる。解除は §4.3 の管理経路で行う。
- 「別プロセスにした」だけでは足りない。**実行ユーザー・ファイルの所有者・設定変更の権限・サービス停止の権限**まで分ける（§7 の手順案）。
- ネットワーク管理の権限は「遮断だけできて解除できない」権限ではない（Linux の CAP_NET_ADMIN も、macOS の pfctl の root も同じ）。だから遮断部は小さく、監査しやすくする。

## 4. 改ざん検知と、止められた時の振る舞い

### 4.1 想定する妨害と対策

| 妨害 | 対策 | 段 |
|---|---|---|
| 監視プロセスを止める | 遮断部側（別ユーザー）の監督が、watch の心拍と**処理の進み（受けたイベント数・最後に処理した時刻）**を見る。監視対象の自己申告（「監視中」表示）だけに頼らない | 二 |
| 自動遮断を OFF、監視対象を外す | 設定・許可を root 所有の場所に置き、変更は §4.3 の管理経路だけで受け付ける | 二 |
| 実行コードを変えて「遮断成功」だけ返す | 遮断部のコードと実行環境を業務ユーザーから書き換え不可にする（root 所有・644/755）。遮断後は OS の状態を読み直して確認し、成功の自己申告を信じない | 一（成功判定の正直化）・二 |
| 復旧処理や台帳を悪用する | **台帳が無い・壊れている時に広く通信を戻さない（第一段で実装）**。復旧の承認を検知・囮側から分離（§4.3） | 一・二 |
| ログを消す・正常を装う | 保護された記録先（遮断部だけが書ける）＋必要な環境では端末外にも。記録の欠落そのものを状態として扱う | 二・三 |

**プロセスが存在すること**と**防御機能が動いていること**は分けて確かめる。確かめる対象は、監視が登録されているか・イベント処理が進んでいるか・承認された設定が有効か・遮断要求が処理されるか・遮断後に対象の通信が実際に止まっているか。
コードの整合性確認（ハッシュ）と動作の確認（試験要求）は両方要る。

### 4.2 止められた時：フェイルクローズにするか

**しない（既定）。** 「Zee の応答が一度途切れたら、無条件でホスト全体を遮断する」は採らない。通常の更新・スリープ・負荷・障害でも業務を止めるうえ、攻撃者に「Zee を少し不調にすればその端末を止められる」という手段を渡す。

| 観測 | 扱い |
|---|---|
| 単発の応答欠落 | 再確認し、異常として表示・通知。遮断しない |
| 認証された保守操作（更新・停止） | 対象と期限を限定して許可（§4.3 の署名つき） |
| 未承認の設定変更・保護機能の破壊が確認された | **利用者が事前に許可した対応方針**へ進む（通知のみ／遮断）。既存の「囮への変更系接触」とは別の条件として、利用者が別途 ON にする。既存設定の意味を黙って広げない |

**フェイルクローズにするのは復旧側だけ**：「記録が無いから全部戻す」をやめ、「判断できないので戻さない」にした（第一段で実装）。正当な緊急復旧手段（`--all-interfaces`）は残す。

**自己試験が本番を誤発火させない**：試験用の遮断要求は、本番の検知イベントと別の種類として遮断部に入れ、試験用の対象（ダミーのルール名・アンカー）にだけ作用させる。本番の資産 ID では受け付けない（第二段）。

**dry_run の既定は変えない。** 遮断部の検証（`refusal`）は dry_run を「遮断不可」として扱い、`handle()` の判定を緩めない。

### 4.3 認証された管理経路（新しい認証方式を作らない）

復旧・設定変更・自動遮断の OFF・遮断部の停止は、**持ち出し承認（`src/zee/egress/`、`docs/design/egress-approval.md`）と同じ部品**で承認する：別端末（iPhone の Secure Enclave 等）の ES256 署名、公開鍵登録簿、要求内容そのものへの署名、番号照合、期限と再利用の拒否。
こうすると、同じユーザーのシェルを奪っただけでは解除できない（鍵が端末に無い）。全承認端末を失った時の回復（72時間待ち）も同じ規則を使う。

正当な所有者が Zee を停止・更新・削除できる経路は必ず残す。守る相手は利用者ではなく、利用者の許可を持たない侵入者。

## 5. 端末外への逃がし（第三段・任意）

ホストの管理者権限まで奪われた場合に残る手段として、**被害端末とは別の管理機器・ゲートウェイ側から、その端末の通信を遮断できる**ようにする。
- 外部の遮断を**解除する資格情報を被害端末に置かない**。別サーバーにしただけで同じ資格情報から全部操作できるなら分離にならない。
- 端末側 Zee からは「遮断要求」を送るだけ。外部側は要求を受けたら遮断し、解除は外部側の管理経路（§4.3 の署名）でだけ行う。
- 置き場所は、10/15 のメーカー組み込み版の構想（ゲートウェイ・ハブ・ルーター）と同じ。そちらの技術資料に「端末側 Zee からの遮断要求を受ける口」として載せられる。
- 外への「正常です」の定期通知だけでは改ざんされていないことは証明できない（通知元が乗っ取られれば正常を装える）。端末外の記録・別の観測・実際の通信状態を組み合わせる。
- 利用者が管理する機器で構成し、必須の有料クラウドにはしない。

## 6. 第一段で実装したもの（この枝）

OS の権限を変える操作・root での実行・実機の pf 有効化は含まない。すべてテストは OS コマンドをモックして実行した。

| 変更 | 場所 | 何が変わるか |
|---|---|---|
| 復旧のフェイルクローズ | `src/zee/recovery/restore.py`・`src/zee/telemetry/cut_state.py`・`src/zee/errors.py`（Z605） | 未解決の遮断記録が無い（ファイルが無い・消された）、または台帳に**形の崩れた行が1行でもある**（読めない・JSON でない・必須項目や型の欠け（`cut_at`・`resolved_at`・`method`・`platform`・`modified`）・`modified` が空・同じ資産の遮断記録で OS が食い違う。どの資産の行かは問わず、全行を検査してから対象の資産を絞る）と、通常の `zee restore` は**何も戻さず拒否**（Z605）し「Zee restore REFUSED」と通知する。旧方式の全面復旧は `zee restore <asset_id> --all-interfaces`（トークン必須のまま）で明示した時だけで、この経路は台帳を読むが、無い・壊れている・読めない時も止まらず、記録なしとして進む（台帳は復旧後の読み直しで「戻っているべき対象」を知るためだけに使う）。**形は正しいが中身が偽の記録**（同じユーザーなら書ける）は検知できない |
| 遮断を重ねても先の記録を失わない | `cut_state.py` | 最後の復旧以降の遮断記録を合算して戻す（先に落とした Wi-Fi が、次の遮断の記録で隠れない） |
| 復旧の成否は OS を読み直して決める（通常・全面の両経路） | `restore.py`・`cut_full.py`（`interface_states`）・`errors.py`（Z606） | **Zee 固有名のファイアウォール規則**（nft の `inet zee_egress`・iptables の `ZEE_EGRESS`・pfctl の `zee-egress-cut` アンカー・netsh の `zee-egress-cut-block` / `-allow-local`）は、**台帳に関係なく**その OS の全バックエンドで削除し、表示コマンドで読み直して不存在を確認する。egress の規則はホスト共通（資産ごとではない）。残っている・読み直せない＝失敗（Z601）。ツールが無くて確認できない＝**未確認（Z606・終了コード1・未解決のまま）**で、成功には数えない。インターフェース・サービスは、復旧後に OS を読み直して名前ごとの状態（有効・無効・不明）を得る。台帳に記録された対象は**「有効」と読めた時だけ**確認済みで、無効なら失敗、一覧に無い（消えた・列挙漏れ）・状態が不明・一覧が読めない／空なら未確認（Z606）。NetworkManager の状態も enabled・disabled・不明の3つで扱い、取得の失敗や時間切れは不明。記録外で無効なものは警告として表示する。全面復旧では、台帳の有無に関係なく**実際に操作した対象**（と、使える記録があればその対象）を読み直す。台帳の各項目は、名前ではなく記録した遮断の方法から種別（インターフェース・サービス／nmcli／ファイアウォール規則）を決める（egress の遮断で記録したものだけが規則。macOS に `zee-egress-cut-block` という名のサービスがあっても、full の遮断で記録したならサービスとして有効化・検証する）。操作した対象の名前は列挙・操作した時点で保持し、表示用の文字列から推定しない（macOS の `Office: Ethernet` のように「:」を含む名前も検証する）。操作した対象の名前が読み直しの一覧で見つからなければ未確認（Z606）。ただし、列挙の時点で取り込めなかった名前は操作も検証もされず、台帳の記録が無ければ「記録外で無効」の警告に出るだけになる（列挙と読み直しは同じコマンド・同じ解析規則にそろえてある）。検証する対象が空、またはすべて確認できなかった場合は成功にしない（一般則）。台帳が egress の規則だけの遮断（インターフェースを変えていない）は、規則の読み直しが検証になる。Linux の `ip` の出力は名前と閉じたフラグ欄まで検証し、途中で切れた行・形の崩れた行のインターフェースは「不明」とする。ツールは PATH に /usr/sbin・/sbin を足して探し、絶対パスにしてから実行する。インターフェースの段は必ず数える（ツールが無い・列挙が0件なら失敗）。nmcli の失敗は結果に残し、NetworkManager 自身が「enabled」と答えた時だけ解除済みとする。`nmcli networking on` が失敗した時は、インターフェースごとの復旧も必ず行う。macOS は無効化済み（`*` 付き）のサービスも有効化する。通知には「台帳は同じユーザーが書き換えられる」ことを毎回書く。ハッシュ連鎖は入れない（同じユーザーが鍵ごと書き換えられるので保証にならない） |
| 一部だけ成功した遮断も記録 | `src/zee/responder/cut_full.py`・`cut_egress.py` | 落とせた分を台帳に記録する（復旧が拒否されないように）。Windows の egress は遮断ルールだけ入って許可ルールで失敗した場合、iptables はチェーン作成後に途中で失敗した場合も記録する。nftables は一括投入のため部分状態を作らない |
| 空の遮断は失敗 | `cut_full.py` | 落とす対象が0件（Linux の `ip`・macOS の `networksetup`）なら成功と言わない |
| 台帳に書けなかった遮断も失敗として知らせる | `cut_full.py`・`cut_egress.py`・`sequence.py` | 台帳の書き込み失敗（ディスク満杯等）で例外を投げず、`os=ok ledger=FAILED`・変更した対象・`--all-interfaces` での戻し方を返し、通知の本文に出す |
| 失敗を「applied」と言わない | `src/zee/responder/sequence.py`・`cut_egress.py` | 遮断が失敗した時の通知の題名を「Zee cut FAILED」にする。macOS の egress は `pfctl -e`（pf の有効化）の失敗も遮断失敗にする（「既に有効」は成功） |
| 遮断部の境界 | `src/zee/responder/blocker.py`（新規） | `CutRequest`（asset_id・op_class・confidence の3項目だけ）と `refusal()`。`handle()` は遮断関数を呼ぶ直前に必ず通す。規則は handle の判定と同じ（緩めない）。いまは同じプロセス内なので権限分離にはならない。第二段で別ユーザーの遮断部がこの規則をそのまま使う |

**手動の `zee cut` は境界を通さない**（`--method` で方法を上書きできる、利用者の権限による操作）。第二段では、遮断部が「自動の要求（厳格）」と「管理経路で署名された手動の要求」の2種類を受ける。いまは自動の方だけを定義した。

**意図して入れなかったもの**：`permission.py` の配線（10/13 に未配線のまま入れる判断がされている）、心拍・監督（同じユーザーで動く監督は、監督対象と一緒に止められるので意味がない。第二段で別ユーザーとして作る）、ソケット・別プロセス化（§7 の承認後）。

テスト：`tests/test_self_defense.py` 184件。段階ごと（独立チェック2回・外部レビュー7回・討論の結論・付録Aの分岐点検）に、追加したテストが修正前のコードで失敗することを確認してから実装した（元から通る確認用の数件を除く）。全体 720 passed / 1 skipped（分岐前の main は 536 passed / 1 skipped）。

<a id="privileged-deployment"></a>
## 7. 【代表承認事項】権限分離を実地に適用する手順案

ここから先は **OS の権限・常駐の仕組みを変える**ため、代表の承認を得てから行う。**下の手順はどれも実行していない。** コマンドは macOS を第一対象とした案で、**実機では未検証**（特に §7.3 のソケット相手の確認方法）。

### 7.1 何をどう分けるか

| 対象 | 所有者・権限 | 業務ユーザーから |
|---|---|---|
| 遮断部の実行コード（Python 本体と zee パッケージ） | root:wheel。ディレクトリと実行ファイル（python 本体）は 755、モジュール（.py）は 644 | 読めて実行できるが書けない |
| 遮断部の設定（assets.toml の写し・自動遮断の許可・承認端末の公開鍵登録簿） | 専用ユーザー `_zeecut`（仮）、700/600 | 読めない・書けない |
| 遮断台帳・遮断部の記録 | `_zeecut`、700/600 | 読めない・書けない |
| 遮断要求のソケット | `_zeecut` 所有、業務ユーザーのグループに書き込みだけ許す | 要求を送れるだけ |
| 常駐の定義（LaunchDaemon の plist） | root:wheel 644、`/Library/LaunchDaemons/` | 止められない（`launchctl bootout system/...` は root が要る） |
| `zee watch`（囮・通知・判定） | 業務ユーザーのまま | 従来どおり |

pf の操作（`pfctl`）と `networksetup` の変更には root が要る。遮断部の常駐全体を root で動かす代わりに、**遮断の2コマンドだけを root で実行できる小さな入口**にする案と、**遮断部を root の LaunchDaemon にして中身を最小に保つ**案がある。前者は sudoers の設定（コマンドと引数を固定）で作れるが、引数の固定が甘いと解除にも使われるので、**推奨は後者**（遮断部のコードが小さく、要求の形が3項目に固定されているため監査しやすい）。

### 7.2 手順案（macOS・未実行）

1. 専用ユーザーを作る：`sudo sysadminctl -addUser _zeecut -fullName "Zee cut service" -shell /usr/bin/false -home /var/empty`（ログイン不可・ホーム無し。作成方法は OS の版で異なるため実行前に確認）
2. 遮断部のコードを root 所有の場所へ入れる：例 `/Library/Application Support/Zee/`（root:wheel 755/644）。業務ユーザーの `uv` 環境とは別の Python を使う
3. 設定・台帳の置き場を作る：例 `/Library/Application Support/Zee/state/`（`_zeecut` 700）
4. `/Library/LaunchDaemons/` に遮断部の plist（root:wheel 644）を置き、`sudo launchctl bootstrap system <plist>` で起動
5. 業務ユーザーの `zee watch` を「遮断要求をソケットへ送る」設定で起動し直す（第二段のコード）
6. 確認：業務ユーザーから設定・台帳を書けない／遮断部を止められない／偽の形の要求が拒否される／**隔離した試験環境で**遮断が実際に成立し、復旧が署名なしでは通らない
7. 戻し方（順序が大事）：①遮断中なら先に管理経路で復旧し、OS の状態（ネットワークサービス・pf のアンカー）が戻ったことを確認する ②それから `sudo launchctl bootout system/<label>` ③plist とディレクトリを退避（削除ではなく `mv`）④専用ユーザーは残すか代表判断。**遮断部を止めたり退避したりしても、OS に入った遮断は戻らない。** 遮断部が起動できない時の救済は、root で `networksetup -setnetworkserviceenabled <サービス名> on` と `pfctl -a zee-egress-cut -F all` を直接実行する（手順書として別に用意する）

Linux では systemd のサービス（専用ユーザー＋`AmbientCapabilities=CAP_NET_ADMIN`・`ProtectSystem=strict`・`ReadWritePaths=` で台帳だけ書ける）が同じ役割になる。ただし現行の Linux 遮断は nmcli（NetworkManager）を優先し、NetworkManager の操作の許可は capability ではなく polkit で決まる。遮断部に capability を付けるだけでは足りず、**業務ユーザーが `nmcli networking on` 等で自分で戻せないか（polkit の設定）も点検対象**にする（遮断部は nmcli を使わず nftables だけにする案も検討）。Windows はサービスアカウント＋サービスの停止権限の ACL。いずれも未検証。

### 7.3 実機で確かめる必要があること（未検証）

- ソケットの相手の uid を OS から得る方法：Linux は `SO_PEERCRED`（Python の `socket` に定数あり）。macOS は `getpeereid()` / `LOCAL_PEERCRED` で、Python から呼ぶ方法は実機で確認が要る
- pf を遮断部が有効化する時、既存の pf 設定（他のソフトのアンカー）を壊さないこと
- スリープ・OS 更新の後に遮断部が自動で戻ること、戻らない時に業務側にその状態が見えること
- 実遮断の試験は、囮ループの指示書（段階A：隔離試験環境での実遮断の成立確認）と**一度の環境構築で兼ねる**。結果は `docs/verification/` の形式で記録する

### 7.4 承認をお願いしたいこと

1. 専用ユーザーの作成と、遮断部を root の常駐（LaunchDaemon）にする方針でよいか（推奨：よい。ただし最初は隔離した試験環境で）
2. 「未承認の設定変更・保護機能の破壊」を新しい自動対応の条件にするか（推奨：作るが既定 OFF、利用者が別途 ON）
3. 管理経路を持ち出し承認の署名と共通化するか（推奨：共通化。新しい認証方式を別に作らない）

## 8. 限界（言い切り）

- 第一段だけでは**同じユーザーの攻撃者は今も Zee を止められる**（`zee watch` を終了させる・assets.toml を書き換える・台帳を消す）。第一段で変わったのは、台帳を消しても**通信が広く戻らなくなった**ことと、遮断失敗や空の遮断を**成功と表示しなくなった**こと。
- ホストの管理者権限を奪われた場合は、第三段（端末外の遮断）まで端末の中では守れない。
- `--all-interfaces` の全面復旧は、Zee 以外が止めていたインターフェースも戻しうる。
- ツールが入っていないバックエンド（例：nft と iptables の片方だけの Linux）では、そちらに Zee の規則が無いことを確かめられないため、復旧は「未確認」（Z606・未解決のまま）になる。通常の Linux でも起こりうる。成功と言わないための代償で、結果の各手順を見て判断する。
- 台帳の検査は形だけ。同じユーザーの攻撃者が**形の正しい偽の記録**を書けば、通常の復旧はその記録どおりにインターフェースを戻す（戻すのは記録に書かれた名前だけで、トークンも要る）。台帳は判定を厳しくする材料にだけ使い、緩める材料にはしない：Zee 固有名の規則は台帳に関係なく削除・確認するので、偽の台帳で規則を隠すことはできない。ただし Zee 固有名ではない遮断（攻撃者が別名で入れた規則など）は対象外で、台帳から抜かれたインターフェースは「記録外」の警告として表示されるだけ。完全に閉じるのは §7 の権限分離。
- 別モデルによる独立チェックを2回受けた（1回目 62点・11件、修正後の再チェック 68点・7件）。その後の外部レビュー2回（高2中1、高2）と、2つのモデルによる討論の結論（OS を読み直して決める・台帳は厳しくする材料にだけ使う）も反映した。**最終版への独立チェックはまだ受けていない**。同じユーザーの攻撃者はトークンを読めるので、通常の復旧も `--all-interfaces` も実行できる点は、文書を正しただけで、根本は §7 の権限分離でしか解けない。
- 「既に無いルール」の判定は各ツールの応答の文字列で行う。ツールの版や表示言語で文言が違えば、既に無いルールが「失敗」と表示される（失敗を成功と誤認する向きにはしていない）。

## 付録A. 復旧・遮断の分岐表（2026-10-15、7回目の外部レビュー後の全分岐の点検）

対象：`src/zee/recovery/restore.py`・`src/zee/responder/cut_full.py`。観点は「ある手順の成功で、別の手順や検証を省いていないか」。判定の記号：✅ 成功、❌ 失敗（Z601／遮断なら FAILED）、❓ 未確認（Z606）。テスト列は `tests/test_self_defense.py` の該当テスト。

### A-1. 復旧の経路と台帳

| OS | 経路 | 台帳 | 何をするか | 判定 | テスト |
|---|---|---|---|---|---|
| 全OS | 通常 | なし／壊れている | 何もしない | Z605（拒否） | `test_restore_without_record_refuses…`・`test_normal_restore_refuses_any_ledger_damage` |
| 全OS | 通常 | あり | 記録の種別ごとに操作（規則以外）→全バックエンドの規則を削除・読み直し→記録した対象を読み直し | 下表 | `test_forged_ledger_*`・`test_normal_restore_enables_and_verifies_service_named_like_a_rule` |
| 全OS | 通常 | あり（egress の規則だけ） | インターフェースの読み直しは行わない（変えていない）。規則の削除・読み直しが検証 | 規則の結果どおり | `test_egress_only_record_restore_still_succeeds` |
| 全OS | 全面 | あり／なし／壊れている | 台帳を読まずに全部を有効化→規則を削除・読み直し→**操作した全対象**と使える記録の対象を読み直し | 下表 | `test_emergency_without_ledger_*`・`test_emergency_restore_works_with_any_ledger_damage` |

### A-2. 手順ごとの成否と読み直し

| 手順 | 結果 | 判定 | テスト |
|---|---|---|---|
| インターフェース・サービスの有効化（全面） | 列挙0件・ツールなし | ❌（Linux で nmcli が成功している時の `ip` なしは ❓） | `test_firewall_success_alone_is_not_a_full_restore`・`test_emergency_nmcli_success_without_ip_is_unverified` |
| Linux の `nmcli networking on`（全面） | 成功 | **個別インターフェースの有効化と読み直しを省かない**（7回目の指摘で修正） | `test_emergency_nmcli_success_still_sweeps_and_reads_back_interfaces` |
| 同上 | 失敗 | 失敗を残す。NM が enabled と答えた時だけ ✅ | `test_nmcli_failure_is_kept_unless_networking_is_confirmed_on` |
| Linux の `ip link set <if> up`（全面） | nmcli が成功した後で失敗（消えた veth など） | その手順は ❓。最終判定はその名前の読み直し（無効 ❌・一覧に無い ❓） | `test_sweep_command_failure_after_working_nmcli_is_decided_by_read_back` |
| 規則の削除（nft・iptables・pfctl・netsh） | 削除の終了コード | 判定に使わない（読み直しで決める） | `test_forged_ledger_rule_removed_then_success` |
| 規則の読み直し | バックエンド自身が「その名前のテーブル／チェーン／規則は無い」と答えた（nft：`Error:` で始まり `No such file or directory` と `zee_egress` を含む。iptables：`No chain/target/match by that name`。netsh：`No rules match the specified criteria`。pfctl：アンカーが空） | ✅ | `test_both_backends_absent_is_success`・`test_nft_absence_needs_backend_specific_answer` |
| 同上 | 規則が表示された | ❌（他のバックエンドも続けて処理） | `test_one_backend_permission_error_continues_then_fails`・`test_rule_still_listed_after_removal_is_failure`・`test_nft_rule_listed_is_present` |
| 同上 | 終了コード 126／127（ローダーエラー等）・権限エラー・形の違う答え | ❓（同じ文言を含んでも「無い」とは読まない。8回目の指摘で修正） | `test_loader_error_is_a_launch_failure`・`test_unreadable_listing_is_unverified_not_absent` |
| macOS の pf アンカー | 新旧両方（`com.apple/zee-egress-cut` と旧 `zee-egress-cut`） | 両方を消して読み直す | `test_restore_flushes_new_and_old_pf_anchor` |
| 同上 | ツールなし | ❓ | `test_no_ledger_nft_missing_iptables_ok_is_unverified`・`test_recorded_nft_with_nft_missing_is_unverified` |
| 対象の読み直し | 有効 | ✅ | `test_readback_needs_positive_enabled` |
| 同上 | 無効 | ❌ | 同上・`test_colon_named_service_is_read_back` |
| 同上 | 不明・一覧に無い・一覧が読めない・空 | ❓ | 同上・`test_interface_states_*`・`test_linux_malformed_ip_line_is_unknown` |
| 同上 | 検証する対象が0件 | ❓（空の検証は成功にしない） | `test_empty_verification_is_never_success` |
| 記録外で有効でないもの | 無効・不明 | 警告として表示（判定は変えない） | `test_readback_outside_record_is_only_a_warning`・`test_unknown_state_outside_record_is_reported` |
| 解決済みの記録 | ✅ の時だけ | ❌・❓ では未解決のまま | `test_recorded_nft_with_nft_missing_is_unverified` |

### A-3. 遮断（`cut_full`・`cut_egress`）

| 手順 | 結果 | 判定 | テスト |
|---|---|---|---|
| 対象0件 | — | FAILED | `test_cut_with_nothing_to_disable_is_not_success` |
| 一部だけ成功・失敗・時間切れ | — | FAILED。**試みた対象はすべて記録**（失敗・時間切れでも効いている可能性があるため。復旧で有効化と読み直しの対象になる。9回目の指摘で修正） | `test_partial_cut_records_the_interfaces_that_went_down`・`test_full_cut_records_attempted_targets_even_when_a_command_fails`・`test_full_cut_records_failed_service_or_adapter` |
| Windows の遮断対象 | Get-NetAdapter の Status が `Disabled` 以外（Up・Disconnected・不明）をすべて対象にする | 読み直しで無効を確認できない対象があれば FAILED（9回目） | `test_windows_cut_targets_every_adapter_not_confirmed_disabled`・`test_windows_cut_not_applied_when_an_adapter_is_not_confirmed_disabled` |
| 全部のコマンドが成功 | 読み直しで全対象が無効 | 成功 | `test_full_cut_is_confirmed_by_read_back` |
| 同上 | 有効・不明・一覧に無い・読めない | **FAILED**（コマンドの成功だけでは遮断と言わない。点検で見つけて修正） | 同上・`test_full_cut_unreadable_state_is_not_confirmed` |
| 読み直しの道具 | Linux で `ip` が無い・Windows で PowerShell が無い | 遮断で使える代わりの道具（nmcli・netsh）でも読み直す。netsh の Admin State が英語以外なら「不明」 | `test_linux_states_keep_nmcli_when_ip_fails`・`test_windows_states_fall_back_to_netsh` |
| 台帳に書けない | — | FAILED（`os=… ledger=FAILED` と戻し方を表示） | `test_ledger_write_failure_is_reported_not_raised` |
| egress 遮断の読み直しの解析（9回目） | コメント・空行を除いて構造を見る。nft：`table inet zee_egress` に `type filter hook output` で `policy drop;` の chain。iptables：`-N ZEE_EGRESS` の中に無条件の `-j DROP`（それより前に無条件 ACCEPT が無い）、OUTPUT の先頭規則が `-j ZEE_EGRESS`。pf：アンカーに `block drop out all` | 形が違えば missing、見出しが無い等で解析できなければ unverified。どちらも FAILED | `test_nft_read_back_checks_hook_and_policy`・`test_iptables_read_back_checks_structure`・`test_pf_read_back_needs_the_outbound_block_rule` |
| egress 遮断（`cut_egress`）の規則の読み直し | 全部確認 | 成功（台帳に `verified: confirmed`） | `test_egress_cut_confirmed_when_rule_reads_back`・`test_iptables_egress_needs_chain_and_jump`・`test_pf_egress_needs_rules_and_pf_enabled` |
| 同上 | 無い（missing）・読めない／ツールなし（unverified） | FAILED。通知の本文に「not confirmed by read-back」と理由。台帳に結果 | `test_egress_cut_not_confirmed_is_failed`・`test_egress_cut_tool_missing_is_unverified`・`test_windows_egress_rule_missing_is_failed`・`test_handle_notifies_unconfirmed_egress_cut` |
| macOS（pf）の成功条件 | アンカー `com.apple/zee-egress-cut` に block があり、pf が有効で、**主ルールセットに `anchor "com.apple/*"`（または Zee のアンカー名）がある** | どれか欠ければ FAILED（参照が無ければ missing） | `test_pf_cut_requires_anchor_reachable_from_main_ruleset`・`test_pf_cut_loads_rules_under_the_com_apple_anchor` |
| Windows の成功条件 | 規則ごとに `Enabled: Yes`・`Direction: Out`・`Action`（block／allow）・block 規則の `RemoteIP` が全範囲、さらに規則の `Profiles` のすべてで `netsh advfirewall show allprofiles state` が ON | 違えば missing、英語以外の項目名などで読めなければ unverified。どちらも FAILED | `test_windows_rule_must_be_enabled_outbound_block_in_active_profiles` |

### A-4. 点検で見つけた追加の穴

1. **full 遮断を読み直していなかった**（コマンドの終了コードだけで「applied」）。修正済み：対象が無効と読めなければ FAILED。
2. **記録外で状態が「不明」のものは警告にも出ていなかった**。修正済み：無効・不明とも警告に出す。
3. **（今回の修正で入れた退行）全面復旧で nmcli が成功した後の個別インターフェースの失敗が、全体を FAILED にしていた**（消えた veth 1つで「復旧失敗」と誤報）。修正済み：その手順は未確認にし、名前ごとの読み直しで決める。
4. **遮断の読み直しが、遮断と同じ代わりの道具を持っていなかった**（Linux で `ip` が無い・Windows で PowerShell が無いと、遮断できていても FAILED）。修正済み：nmcli・netsh でも読み直す。
5. **macOS の egress 遮断が評価されていなかった**（8回目の外部レビュー）。pf は主ルールセットから参照されたアンカーしか評価しない（出典：OpenBSD pf.conf(5) の ANCHORS 節 https://man.openbsd.org/pf.conf ）。macOS の標準 `/etc/pf.conf` は `anchor "com.apple/*"` を参照するだけで、Zee が規則を入れていた最上位の `zee-egress-cut` は参照されていなかった（開発機の `/etc/pf.conf` で確認）。修正済み：`com.apple/zee-egress-cut` に入れ、主ルールセットからの参照を読み直して確認。主ルールセットを Zee が書き換えることはしない（利用者の設定を壊すため）。参照が無い環境では FAILED と表示する。**実機での遮断の成立は未確認**（§7.3 の隔離環境で確かめる）。
6. **Windows の egress 遮断を規則名の存在だけで成功にしていた**（8回目）。修正済み：有効・方向・動作・範囲と、適用先プロファイルのファイアウォールが ON かを確認（出典：Microsoft Learn「netsh advfirewall」 https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-advfirewall ）。`RemoteIP` の表示形式は実機で確かめていない（`0.0.0.0/0`・`0.0.0.0-255.255.255.255`・`Any` 以外なら missing＝FAILED に倒す）。
7. **復旧の読み直しが「No such file or directory」という文言だけで規則なしと判定していた**（8回目）。nft の共有ライブラリが無い時（終了 127）も同じ文言が出る。修正済み：終了 126／127 は起動失敗、バックエンド固有の形の答えだけを「無い」とし、それ以外は未確認。
8. **egress 遮断（`cut_egress.py`）が規則を入れたあと読み直していなかった**（コマンドの終了コードで「applied」）。修正済み：同じバックエンドの表示コマンドで Zee 固有名の規則を読み直し（nft はテーブルに drop、iptables はチェーンの DROP と OUTPUT からの jump、pfctl はアンカーの block と pf の有効、netsh は各ルール名）、確認できた時だけ applied。ツールが「無い」と答えたら missing、ツールが無い・読めない・形が違えば unverified で、どちらも FAILED と通知に書く。台帳の遮断記録に読み直しの結果（`verified`: confirmed／missing／unverified）を残す（full 遮断も同じ。full では、まだ有効と読めた＝missing、読めない・不明＝unverified）。pf のアンカーが空なら missing。ツールの出力が読めない文字コードでも例外で止まらず（置き換えて読む）、台帳と通知まで必ず進む。
9. **未対応**：Linux の full 遮断は `nmcli networking off` が成功すると `ip link down` を行わず、確認も NetworkManager の状態だけ。NetworkManager の管理外のインターフェースは止まらない可能性がある（実機での確認が要る。§7.3 の隔離環境で確かめる）。

### A-5. 残る既知の限界（実機未確認の項目の一覧）

この枝のテストはすべて OS コマンドを模擬して実行した。**実機（Linux・macOS・Windows）で遮断と復旧を実際に動かしてはいない。** 以下は、§7.3 の隔離試験環境で確かめるまで「設計上そうなるはず」の段階にあるもの。どれも、確かめられない時は成功と表示しない側（FAILED／未確認）に倒してある。

1. **macOS：`com.apple/zee-egress-cut` に入れた規則が実際に通信を止めるか。** 主ルールセットの `anchor "com.apple/*"` の後に quick 付きの通過規則が他のソフトから入っていれば、Zee の block は上書きされうる（pf は quick が無ければ最後に一致した規則が勝つ）。Zee は主ルールセットを書き換えない。
2. **Windows：netsh の表示形式。** `show rule` の `RemoteIP` の表示（Zee が入れた5つの範囲と同じ並びでなければ FAILED）、項目名、`show allprofiles state` の形式。英語以外の表示では未確認＝FAILED になる。
   - **GitHub Actions の Windows ランナーでの実測（2026-10-15、commit 238fb0e）で、Zee の Windows の egress 遮断はそもそも成立していなかったことが分かった**：netsh は `remoteip=0.0.0.0/0` を「IP アドレスが無効」として受け付けず、遮断の規則が入らなかった（Zee はこれを FAILED と表示し、通信は止まらなかった）。加えて Windows ファイアウォールでは block の規則が allow の規則より優先されるため、「全部 block＋ローカルだけ allow」の2規則の作りはローカルも止めてしまう。修正：RFC 1918 と 127/8 を除いた IPv4 の5範囲を1つの block 規則で止める（`WINDOWS_BLOCK_RANGES`）。修正後の実測（run 38739379077、commit e226127）では Windows ランナーで通信が止まり、復旧で戻った。netsh が表示した `RemoteIP` は Zee が入れた5範囲と一致し、Zee 自身の読み直しも confirmed だった。
3. **Windows：Get-NetAdapter の状態。** `NotPresent` 等の状態の機器があると、遮断は無効を確認できず FAILED になる（安全側だが、誤報になりうる）。
4. **Linux：`nmcli networking off` が NetworkManager の管理外のインターフェースを止めるか。** 遮断の確認は NetworkManager の状態だけ（付録A-4）。
5. **Linux：nft・iptables の出力形式。** nft の版による表記の違い（priority の名前表記など）、iptables-legacy と iptables-nft の `-S` の違い。想定と違えば未確認＝FAILED。
6. **IPv6。** この枝の egress 遮断と復旧・読み直しは IPv4 の規則だけを扱う（IPv6 は別の枝 `fix/egress-ipv6` で作業中。統合時に読み直しも合わせる必要がある）。
7. **読み直しの時間差。** コマンド直後は OS の状態がまだ変わっていないことがある（無線の再接続など）。その場合、遮断・復旧は FAILED／未確認と表示される（成功に化ける向きではない）。
8. **「無い」の判定の文言。** 規則が無いことの判定は各ツールの英語の応答文に頼る。表示言語や版で文言が違えば未確認になる。
9. **規則本体への追加・並べ替えによる迂回。** 読み直しは Zee の規則の形（nft の hook と policy、iptables の無条件 DROP とその前の無条件 ACCEPT（コメントは無視）・OUTPUT の先頭、pf の block 行）を見るが、同じユーザー以上の権限の攻撃者が、条件付きの通過規則を chain／アンカーの中や前に足した場合までは検出しない。
10. **Linux の ip link 遮断の対象。** 遮断の時点で既に止まっていたインターフェースも対象として記録され、復旧で上げてしまう（この枝以前からの挙動。遮断前の状態を読んで UP のものだけを対象にするのが次の手）。
11. **権限分離は未適用（§7）。** 同じユーザーの攻撃者は復旧トークンを読んで復旧でき、形の正しい偽の台帳でインターフェースを記録から外せる（その場合は「記録外で無効」の警告に出るだけ）。
