# 設計（確定版）：権限分離 — root の遮断部と、業務ユーザーの zee watch

状態：**試作を v0.14.0 に同梱（既定オフ・`[privsep]` を書いた時だけ有効）**。作者の実機には未適用、確認は GitHub Actions の使い捨てランナーのみ。
**代表の開発機（macOS）には一切適用していない**（ユーザー作成・LaunchDaemon・pf・sudo のどれも実行していない）。OS に効く試験は GitHub Actions の使い捨てランナーだけで行った（§9）。
作成：2026-10-16
元：`docs/design/self-defense.md` §7（権限分離の手順案）と、その §7.4 への代表の承認（2026-10-15、推奨どおり）。

> 「確認済み」は作者がリポジトリ・開発機・CI ランナーで実際に見たもの。「未検証」は見ていないもの。

## 0. 承認された3点と、この文書での答え

| 承認（2026-10-15） | この試作 |
|---|---|
| ① 専用ユーザー＋遮断部を root 常駐（macOS LaunchDaemon／Linux systemd）。最初は隔離した試験環境で | 遮断部 `zee privsep daemon` を root の常駐にし、業務ユーザー（`zee watch` を動かす人）と分けた。常駐の定義は `examples/privsep/`。試験は CI ランナーだけ（§9） |
| ② 「未承認の設定変更・保護機能の破壊」を自動対応の条件に。作るが既定 OFF | 遮断部が自分で観測する2条件（§6）。既定は「記録と状態表示だけ」。遮断に進むのは署名付きの `tamper_set` で ON にした時だけ |
| ③ 管理経路の署名は持ち出し承認と同じ部品。新しい認証方式は作らない | `src/zee/egress/engine.py` の `Engine` をそのまま継承（`AdminEngine`）。署名対象の計算（`payload_digest`）・検証（`OpensslVerifier`、ES256）・公開鍵登録簿・請求の一回使用・期限・番号照合・使用済み台帳は同じコード（§5） |

## 1. プロセス境界

```
業務ユーザー（例：zeework。侵害されうる）
  zee watch：囮の観察・通知・判定（従来どおり）
     │ 遮断要求 {"op":"cut","asset_id","op_class","confidence"}（事実だけ。方法も対象も選べない）
     │ 状態確認 {"op":"status"}（30秒ごと。遮断部にとっての心拍）
     │ 管理（復旧・設定変更・自動遮断の切替・自己防衛の切替・停止・鍵の追加削除）
     │   = {"op":"challenge"} で請求を受け取り → 別端末で署名 → {"op":"submit"}
     ▼ Unix ドメインソケット（macOS /var/db/zee/cutd.sock・Linux /run/zee/cutd.sock。root 所有・業務ユーザーだけの専用グループに 0660。
     │   ソケットのディレクトリが root 所有・グループ／他から書けず、その上のどのディレクトリも
     │   他人が名前を変えられない（root 所有で書けない、または /tmp のような sticky）時だけ起動する。
     │   書かれたままの経路と解決後の経路の両方で確かめ、途中のシンボリックリンクも root 所有に限る。
     │   以後の bind・chown・chmod は確かめた解決後の経路で行う。macOS の /var/run のように
     │   gid 0 以外のグループが書けるディレクトリは許さない（Codex 8回目：uid の大小でグループを信用しない）。
     │   リンクは1段ずつたどり、途中のリンク（連鎖の中間を含む）とそれが置かれたディレクトリをすべて確かめる。
     │   業務側も、接続した相手の uid が 0 であることをカーネルから確かめてから送る（差し替えたソケットに
     │   「遮断した」と嘘をつかせない）。送った後に返事が来なければ「遮断の結果は不明」と通知し、
     │   「何も遮断していない」とは言わない。管理の CLI も同じで、届かなければ Z710、届いて返事が無ければ Z720）
遮断部（root の常駐。src/zee/privsep/daemon.py）
  1. 相手の uid をカーネルから得る（§2）。cut／status／challenge／submit は --allow-uid の uid（と root）だけ
  2. 要求の形を検査（1行 16KiB まで・JSON オブジェクト・項目と型を固定。余分な項目は拒否）
  3. 遮断の判断は自分の持ち物だけで：root 所有の assets.toml の写し・自動遮断の許可
     （responder/permission.py の decide）・遮断の境界（responder/blocker.py の refusal）
  4. 遮断・復旧は既存の cut_full／cut_egress／restore をそのまま呼ぶ（読み直し判定も同じ）
  5. 台帳（cut_state.jsonl）・管理の記録（admin.jsonl）は遮断部の状態ディレクトリにだけ書く
```

受け付ける要求は **`cut`・`status`（署名なし）** と、**`challenge`・`submit`（署名の経路）**、**`bootstrap_key`（相手が root の時だけ）** の5つ。`challenge`・`submit` も許可された uid と root だけ（4ペルソナ・レビュー：誰でも請求を作れると、他人の承認待ちを追い出し、root の記録でディスクを埋められた）。請求は uid ごとに未処理4件まで（超えたらその uid 自身の古いものを捨てる）・`challenge` と `submit` はそれぞれ uid ごとに1分に10件まで（Codex 6回目：署名なしの偽の `submit` で root の記録を増やせたため）。`status` は全体のロックの外で答える（遅い遮断・復旧の間も watch の心拍が詰まらない）。返答の失敗には `code`（Z711〜Z718、`docs/maintenance/privsep_install.md` §7）を付ける。`restore`・`stop`・`auto_set` 等を署名なしで送っても `unknown_op`（テストと CI で確認）。

業務側（`zee watch`）は、assets.toml に `[privsep] socket = "..."` がある時**だけ**遮断部へ要求を送る。無ければ従来どおり同じプロセスで遮断する（`Config.privsep_socket` が None。既定の動作は変えていない。`tests/test_privsep.py::test_handle_uses_privsep_only_when_given`）。遮断部に届かなければ通知の題名は「Zee cut FAILED」になり、「届かなかった・Zee は何も遮断していない」と本文に出す（成功とは言わない）。

## 2. 相手の確認（ソケットの相手の uid）

- **Linux：`SO_PEERCRED`**。`getsockopt(SOL_SOCKET, SO_PEERCRED)` が `struct ucred {pid, uid, gid}` を返す。値は相手が `connect(2)` した時点のもの（一次情報：man7.org の unix(7)「SO_PEERCRED」節、2026-10-16 取得）。
- **macOS：`LOCAL_PEERCRED`**（レベル `SOL_LOCAL`＝0）。`struct xucred {u_int cr_version; uid_t cr_uid; short cr_ngroups; gid_t cr_groups[16]}` が返る。man 4 unix は「相手は適切なシステムコールを別の実効資格で呼ぶ以外に、渡る資格情報に影響できない」と書く（一次情報：開発機の `man 4 unix`・`man getpeereid`、SDK の `sys/un.h`（`SOL_LOCAL 0`、`LOCAL_PEERCRED 0x001`）・`sys/ucred.h`（`XUCRED_VERSION 0`））。Python には `socket.LOCAL_PEERCRED` があり、開発機で socketpair に対して 76 バイト・`cr_version 0`・自分の uid が返ることを確認済み。`cr_version` が 0 以外なら拒否する。
- どちらでもない OS では相手を確認できないので**要求を受け付けない**（推測しない）。
- **ソケットのファイル権限は認可に使わない**：unix(7) は BSD 系がソケットの権限を無視しうると書く。ファイル権限（0660・グループ）は入口を狭める補助で、判定は uid。CI では、ソケットを開ける（グループに入っている）が許可されていない uid が `peer_not_allowed` で拒否されることを両 OS で実測する。

## 3. 台帳・設定・鍵の所有者と権限

self-defense.md §7.1 は「遮断部の状態は専用ユーザー `_zeecut` の所有」としていたが、**遮断部そのものを root で動かす**（①の承認）ので、状態も root 所有にした。専用ユーザーは**業務側**（`zee watch` を動かす人）を指す。

| 対象 | 置き場所（Linux／macOS） | 所有者・権限 | 業務ユーザーから |
|---|---|---|---|
| 遮断部のコード | `/opt/zee/src`／`/Library/Application Support/Zee/src` | root、ディレクトリ 755・ファイル 644 | 読めるが書けない |
| Python 本体 | `/usr/bin/python3` 等 | **root 所有であること**（業務ユーザーが書ける Python を root で動かすと、その人に root を渡す）。**root で動かす時は必ず `-P -s`**（作業ディレクトリとユーザーの site-packages を import しない）で、`cd /` から、ファイルは絶対パスで。付けないと、業務ユーザーが書ける場所に置いた `zee/__main__.py` が root で動く（4ペルソナ・レビューで再現、CI で毎回確認）。常駐の定義（plist・unit）にも `-P -s` を入れた | 書けない |
| 状態ディレクトリ | `/var/lib/zee-cutd`／`/Library/Application Support/Zee/cutd` | root、700 | 一覧も読めない |
| 　承認済みの assets.toml | 同上 `assets.toml` | root、600 | 読めない・書けない |
| 　自動遮断の許可 | 同上 `auto_containment.json`（permission.py の形式） | root、600 | 同上 |
| 　承認端末の公開鍵登録簿・使用済み署名 | 同上 `admin_keys.json`（egress と同じ形式） | root、600 | 同上 |
| 　遮断台帳・管理の記録 | 同上 `cut_state.jsonl`・`admin.jsonl` | root、600 | 同上 |
| 　自己防衛の設定 | 同上 `tamper.json` | root、600 | 同上 |
| ソケット | macOS `/var/db/zee/cutd.sock`・Linux `/run/zee/cutd.sock`（ディレクトリ 755、root 所有。macOS の `/var/run` は root:daemon 0775＝root 以外のサービスアカウントが書けるので使わない） | root:専用グループ（業務ユーザーだけ。macOS の `staff` は全員なので使わない）、660 | 接続できるだけ |
| 常駐の定義 | `/etc/systemd/system/zee-cutd.service`／`/Library/LaunchDaemons/io.github.kamanoi.zee-cutd.plist` | root、644 | 止められない |
| 承認端末の秘密鍵 | 別端末（iPhone の Secure Enclave・FIDO キー等） | 端末の外 | 無い |

**復旧トークン（`~/.zee/restore_token`）はこの構成では使わない**。業務ユーザーが読めるため、復旧の権限にならない。

## 4. 遮断の要求（署名なし）

- 要求に入るのは `asset_id`・`op_class`・`confidence` の3つだけ（各 128 文字以内の文字列）。`method`・対象のインターフェース等を足すと形の違反で拒否。
- 遮断部は承認済みの assets.toml から資産を探し、`permission.decide`（モード contain・確信度 high・op_class change・dry_run でない・自動遮断の許可が ON で、許可した時の方針のハッシュと一致）と `blocker.refusal` の両方を通った時だけ、その資産の `cut_method` で遮断する。
- 自動遮断の許可は**署名付き `auto_set on`** でしか ON にならない。承認済みの設定を差し替える（`config_set`）と方針のハッシュが変わり、もう一度 `auto_set on` するまで遮断は `policy_mismatch` で拒否される。
- 乗っ取られた watch が嘘の「change」を送れば遮断は起きる（self-defense.md §3 のとおり。業務停止の向きの被害で、利用者が自動遮断を許可した範囲に限る）。解除は署名付きの復旧だけ。

## 5. 管理経路の署名（持ち出し承認の部品の再利用）

`AdminEngine(Engine)` が変えたのは次の4点だけ。egress 側の変更は、`CONFIG_OPS` とファイル名をクラス属性にしたこと（既存の egress のテストは無変更で通る）。

1. 受け付ける操作（`OPS`）：`restore`（asset_id・scope=recorded/all）・`config_set`（path・sha256）・`auto_set`（on/off）・`tamper_set`（off/egress/full）・`stop`・`key_add`・`key_remove`。egress の `allow_*`・`protect_*`・`disable` は受け付けない。
2. 請求の本文に `"aud": "zee-cutd-admin-v1"` と `"host"` を必ず入れる。承認端末の画面で持ち出し承認と取り違えないためと、署名対象を区別するため。
3. 状態ファイル名（`admin_keys.json`・`admin.jsonl`）。
4. 請求を出せるのは許可された uid と root だけで、uid ごとに未処理4件・1分に10件まで（§1）。他の uid の請求は捨てない。

**取り違え・再送への答え**（どれも `Engine.submit` の既存の検査）：遮断部が自分で発行した請求（16バイト乱数の nonce・請求 ID）と**全項目が一致**しない応答は拒否（`payload_mismatch`／`unknown_request`）。請求は一度使うと消え、使用済みの署名ダイジェストは承認を実行する**前に**ディスクに保存する（`replay`）。期限切れは拒否。照合コード（2桁）は請求を出したホストの画面にだけ出し、承認端末で入力した値が署名対象に入る（`code_mismatch` は署名検証の後に見る）。持ち出し承認の請求に付いた署名をこちらに出しても、こちらが発行した請求ではないので `unknown_request`（テストで確認）。

**古い署名を後の状態に使わせない（Codex 1・2回目の指摘）**：遮断部は**請求の発行時に**次の値を署名対象へ入れ（要求者は指定できない）、実行の直前に読み直して一致しなければ実行しない。
- 全操作：管理操作の世代（`gen`、状態ディレクトリの `admin_gen`。署名付きの操作を実行するたびに1増える）。**新しい承認が1つでも実行されると、それより前に発行された未使用の請求はすべて無効**になる（「OFF にした後で、取っておいた古い ON の署名を出す」等を防ぐ）。
- `auto_set`：承認済みの assets.toml の SHA-256（設定を差し替えた後に古い ON は通らない）。
- `restore`：遮断台帳全体の SHA-256（新しい遮断の後に古い復旧は通らない。egress の規則はホスト共通なので資産ごとではなく台帳全体）。台帳は大きさの上限なしに逐次ハッシュする。
`config_set` は自動遮断を OFF にする（新しい設定は古い許可の対象外）。資産 ID は `[A-Za-z0-9._-]{1,64}` に限る（root の通知・台帳に入るため）。

**一つの署名で一回だけ試す**：復旧が失敗（Z601）・未確認（Z606）でも署名は使用済みになる。やり直すには新しい請求に署名する。

**最初の鍵**：`cd / && sudo env PYTHONPATH=<root 所有の src> <root 所有の python3> -P -s -m zee privsep bootstrap-key --public-key /絶対パス/pub.pem` で実行（相手の uid が 0 の時だけ受け付ける。登録簿が空の時だけ）。2台目以降は署名付き `key_add`。

**全承認端末を失った時**：持ち出し承認の「72時間待ちの回復」（`recovery_start`）は署名なしで始められるので、**ソケットには出さない**（業務ユーザーが始めて72時間後に登録簿を空にし、誰も復旧できない状態を作れるため）。代わりに、正当な所有者が root でコンソールから：①遮断部を止める（`launchctl bootout`／`systemctl stop`）②`admin_keys.json` を `mv` で退避 ③起動して `bootstrap-key` で登録し直す。root を持つ人は元から全部できるので、新しい権限は生まない。

`key_remove` は、遮断部では「ON の間は2台未満にしない」の規則が効かない（その規則は持ち出し承認の ON/OFF を見ているため）。最後の1台は消せない（既存の規則）。

## 6. 条件②：未承認の設定変更・保護機能の破壊（既定 OFF）

遮断部が**自分で観測できること**だけを条件にする（監視対象の自己申告に頼らない）。30秒ごとに確認する。

| 所見 | 何を見るか |
|---|---|
| `watch_config_unapproved` | 業務側の assets.toml（`--watch-config` で常駐の定義に書いた場所）の**バイト列の SHA-256** が、承認済みの写しと違う。方針のハッシュ（`policy_hash`）ではなくバイト列で比べる：`policy_hash` は `dry_run` を含まないが、業務側の `dry_run` を true にするのはまさに「保護機能を外す」操作だから |
| `watch_config_unreadable` | 上のファイルが読めない・消えた |
| `watch_silent` | 一度でも心拍（watch の uid からの `status`）を受けた後、`--tamper-grace`（既定 300 秒）を超えて来ない。起動直後で一度も来ていない間は所見にしない |

- 所見は**常に**状態（`zee privsep status` の `findings`）と管理の記録に出す。防御が失われたのに正常に見せない。
- **ON にした時の注意**：業務ユーザーの assets.toml を書き換えてから `config_set` が承認されるまでの間と、`zee watch` を `--tamper-grace`（300 秒）より長く止めた時（更新・再起動を含む）は、正当な操作でも遮断しうる。設定変更や watch の停止の前に `tamper_set action=off` を承認する（手順書 §4）。導入時も、業務側の `[privsep]` を先に足してから写しを作る（手順書 §1）。
- **自動対応は既定 OFF**（`tamper.json` が無い・読めない＝off）。署名付きの `tamper_set egress|full` で ON。ON の時は、**2回続けて**所見があった時に1回だけ遮断する（self-defense.md §4.2：単発の欠落では遮断しない）。所見が消えたら次の事件として数え直す。遮断は台帳に固定の資産名 `zee-tamper` で記録し、署名付きの `restore asset_id=zee-tamper` で戻す。
- 承認済みの設定が `dry_run = true` なら、自動対応も「would cut」と記録するだけで遮断しない（dry_run の既定は変えない）。
- 既存の「囮への変更系接触」による自動遮断とは別の条件で、既存の設定の意味は変えていない。

## 7. 停止と再起動

署名付き `stop` で遮断部は終了コード 0 で終わる。systemd は `Restart=on-failure`、launchd は `KeepAlive = {SuccessfulExit = false}` なので、正常終了は再起動されず、異常終了は再起動される。業務ユーザーは root のプロセスにシグナルを送れず（`kill` は EPERM）、`systemctl stop`・`launchctl bootout system/...` も通らない（CI で実測、§9）。

**遮断部を止めても OS に入った遮断は戻らない**。遮断中なら先に署名付きの復旧をしてから止める。

## 8. 移行手順と戻し方（代表の手が要る工程。**実行していない**）

手順書：`docs/maintenance/privsep_install.md`。要点だけここに置く。

1. 隔離した試験環境（使い捨ての VM・CI）で §9 と同じ確認を通す（済：CI）。
2. 実機に入れる前に：承認端末の鍵を用意する（試作は openssl の P-256 鍵で検証。iPhone の WebAuthn アダプタは未実装＝egress-approval.md §11 と同じ）。
3. 業務ユーザーの assets.toml に `[privsep] socket = ...` を**先に**足して完成させる（承認済みの写しは同じバイト列でなければ `watch_config_unapproved`）。
4. root で（`cd /`・`python3 -P -s`）：コードと Python を root 所有の場所へ／状態ディレクトリ（700）と承認済みの assets.toml（600）を作る／常駐の定義を置いて起動／`bootstrap-key`。`zee watch` を起動し直す。
5. 署名付き `auto_set on`（自動遮断を使う場合）。

**戻し方**（順序が大事）：①遮断中なら署名付きの `restore`、OS の状態が戻ったことを確認 ②署名付き `stop`（または root で `launchctl bootout`／`systemctl disable --now`）③業務側の `[privsep]` を外して `zee watch` を起動し直す（従来の同一プロセスの遮断に戻る）④常駐の定義・状態ディレクトリ・コードを `mv` で退避（削除しない）。遮断部が起動できない時の救済は self-defense.md §7.2 の 7 と同じ（root で直接 `pfctl -a com.apple/zee-egress-cut -F all` 等）。

## 9. 実測（GitHub Actions の使い捨てランナー）

`.github/workflows/privsep.yml`＋`scripts/privsep_ci.sh`。main への push（遮断部・CI の関連ファイルが変わった時）と手動実行で走る。PR では走らない（フォークの PR にランナーの root を触らせない）。結果は §11 に run 番号つきで書く。

- **Linux（ubuntu-24.04）**：`examples/privsep/zee-cutd.service` をそのまま systemd に入れ、ネットワーク名前空間の中で root の遮断部を動かす（`NetworkNamespacePath`。ランナー自身の通信は切らない）。業務ユーザー `zeework` が `zee watch` を動かし、囮に書き込む → 遮断部が egress 遮断 → 名前空間から試験サーバーへ届かない → 遮断中に業務ユーザーが ①署名なしの復旧要求 ②自分の `zee restore --all-interfaces`（遮断した名前空間の中で）③`nft delete table inet zee_egress` を試し、どれも拒否されて届かないままであることを1つずつ確かめる → 署名付き復旧 → 届く。root で動かすコマンドは、作業ディレクトリに偽の `zee` を置いても読まれないこと（`-P -s` なしでは読まれることも対照として）を確かめる。ほかに：業務ユーザーから状態ディレクトリの一覧・台帳と承認済み設定への書き込み・承認鍵の読み取り・コードへの書き込みができない／`kill` と `systemctl stop` が通らず遮断部が動き続ける／ソケットを開けるが許可されていない uid が拒否される／自動遮断の許可前の遮断要求が拒否される／同じ署名の再送が拒否される／署名付き停止で止まり再起動されない。
- **macOS（macos-latest）**：`examples/privsep/io.github.kamanoi.zee-cutd.plist` を LaunchDaemon として `launchctl bootstrap system` で読み込み、`dscl` で作った業務ユーザーとランナーのユーザー（ソケットは開けるが uid が許可されていない）で、LOCAL_PEERCRED による相手の確認・権限・停止・署名の経路を確かめる。**実遮断はしない**（macOS の遮断の実測は real-cut.yml の範囲）。

## 10. 限界（言い切り）

- **代表の Mac には入れていない**。実機での LaunchDaemon・スリープ復帰・OS 更新後の挙動は未検証。
- root を取られたら守れない（self-defense.md §2 の段階 B。端末外の遮断は第三段）。
- 承認の画面は未実装（WebAuthn アダプタ・承認ページ＝egress-approval.md §11 と同じ）。試作の署名は openssl の鍵で行う。承認端末の画面を乗っ取られた場合の限界も egress-approval.md §3(5) と同じ。
- 業務ユーザーは嘘の遮断要求で遮断を起こせる（§4）。同時接続は「許可された uid（watch・root）」と「それ以外」で別々に 16 本までで、上限を超えた接続はスレッドを作らずに閉じ、要求1行は全体で 5 秒以内に読めなければ切る（Codex 3回目の指摘）。ほかの利用者が watch の遮断要求を締め出すことはできないが、**業務ユーザー自身**は自分の枠を埋めて署名付きの復旧を遅らせられる（その間は root のコンソールで止める・戻す）。遮断と管理の処理は1つのロックで順に行う。
- root で動く遮断部が出す macOS の通知（osascript）は、ログイン中の利用者の画面には**届かない前提**で設計している（未検証。遮断・復旧の結果は返答・台帳・管理の記録で確かめる）。業務側の `zee watch` は、遮断部に接続できなくなった時と戻った時に1回ずつ、利用者の通知と webhook で知らせる。
- `watch_silent` は「status が来ない」ことしか見ない。watch が心拍だけ送り続けて囮の監視を止める改ざんは検出しない（プロセスの存在と防御の動作は別、の残り）。試験用の遮断要求（self-defense.md §4.2）は未実装。
- 遮断部の状態は起動時に一度読む（egress の Engine と同じ単一プロセス前提）。root が稼働中に状態ファイルを直接書き換えた場合の整合は扱わない。
- Linux の full 遮断は NetworkManager を使う。業務ユーザーが polkit の許可で `nmcli networking on` を実行できる環境では、遮断部と無関係に戻せる（self-defense.md §7.2 の注意と同じ）。CI の実測は egress（nft）だけ。
- Windows は対象外（サービスアカウントと ACL の設計は未着手）。

## 11. 実測の記録

（4ペルソナ・レビュー後の再測定を下に追記する。それより前の run 38770329531 の記録は、遮断中の署名なし復旧を実際には試していなかった＝「拒否された署名なし復旧の後もまだ届かない」の項目は常に PASS する形だったため、取り下げた。）

外部レビュー（Codex、`~/claude-bridge/outbox/20261016-zee-privsep/`）：1回目 高4・中1 → 2回目 高1・中2 → 3回目 中1 → 4回目 指摘なし（ここまで 4ペルソナ・レビュー前）。
