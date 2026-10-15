# 手順書：権限分離（root の遮断部）を入れる・戻す — v0.14.0 同梱の試作・既定オフ

設計：`docs/design/privsep.md`。**この手順はどれも代表の開発機で実行していない。** 使い捨ての VM か、
GitHub Actions（`.github/workflows/privsep.yml`）で同じ確認が通ってから、実機に入れるかを決める。
root の操作を含むので、実行するのは機械の正当な所有者だけ。下の `<業務ユーザー>` は `zee watch` を動かすユーザー。

## root で Python を動かす時の決まり（全コマンド共通）

**root で動かすコマンドは必ず次の形にする**：

```sh
cd / && sudo env PYTHONPATH=<root 所有の zee の src> <root 所有の python3> -P -s -m zee ...
```

- `-P`：作業ディレクトリ（と `python -m` の時のカレント）を import の対象にしない。付けないと、
  業務ユーザーが書ける場所（鍵ファイルを置いたディレクトリ等）に `zee/__main__.py` を置かれた時、
  **それが root で実行される**（4ペルソナ・レビューで再現。CI でも「付けないと実行される／付けると実行されない」を毎回確かめる）。
- `-s`：ユーザーの site-packages を読まない（macOS の sudo は HOME を引き継ぐため）。
- `cd /`：念のため、業務ユーザーが書けない場所から実行する。ファイル（公開鍵など）は**絶対パス**で渡す。
- Python 本体も root 所有のものを使う（macOS の Homebrew の Python は業務ユーザーの所有なので**使わない**）。

## 0. 先に用意するもの

- 承認端末の P-256 鍵。試作では openssl で作った鍵（`openssl ecparam -name prime256v1 -genkey -noout -out k.pem`、
  公開鍵は `openssl ec -in k.pem -pubout -out pub.pem`）。**秘密鍵はこの機械に置かない**（別の端末・別の機械で署名する）。
- **専用のグループ**（例 `zeecut`）を作り、`<業務ユーザー>` だけを入れる。ソケットはこのグループにだけ開く。
  macOS の `staff`（ユーザーの既定のグループ）は全員が入っているので**使わない**（接続できても uid で拒否されるが、入口は狭くする）。

## 1. 業務ユーザー側の assets.toml を先に仕上げる

**遮断部に渡す承認済みの写しは、業務ユーザーの assets.toml と同じバイト列でなければならない**
（違うと遮断部は `watch_config_unapproved` を出し続け、自己防衛を ON にしていると遮断に進む）。だから最初に、
業務ユーザーの assets.toml に次を足して完成させてから、§2／§3 でそれを写す。

```toml
[privsep]
socket = "/var/db/zee/cutd.sock"   # macOS。Linux は "/run/zee/cutd.sock"
```

## 2. macOS（LaunchDaemon）

```sh
cd /
Z="/Library/Application Support/Zee"
sudo mkdir -p "$Z" && sudo cp -R <リポジトリ>/src "$Z/" && sudo chown -R root:wheel "$Z" && sudo chmod -R go-w "$Z"
sudo install -d -m 700 -o root -g wheel "$Z/cutd"
sudo install -m 600 -o root -g wheel <業務ユーザーの assets.toml の絶対パス> "$Z/cutd/assets.toml"
# examples/privsep/io.github.kamanoi.zee-cutd.plist の PYTHON_BIN（root 所有の python3）/ WATCH_UID（id -u <業務ユーザー>）/
# WATCH_GROUP（専用グループの gid）/ WATCH_CONFIG（業務ユーザーの assets.toml の絶対パス）を書き換えて：
sudo install -m 644 -o root -g wheel io.github.kamanoi.zee-cutd.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/io.github.kamanoi.zee-cutd.plist
cd / && sudo env PYTHONPATH="$Z/src" <root 所有の python3> -P -s -m zee privsep bootstrap-key \
  --key-id phone --public-key /絶対パス/pub.pem
```

## 3. Linux（systemd）

```sh
cd /
sudo mkdir -p /opt/zee && sudo cp -R <リポジトリ>/src /opt/zee/ && sudo chown -R root:root /opt/zee && sudo chmod -R go-w /opt/zee
sudo install -d -m 700 /var/lib/zee-cutd
sudo install -m 600 <業務ユーザーの assets.toml の絶対パス> /var/lib/zee-cutd/assets.toml
# examples/privsep/zee-cutd.service の WATCH_UID / WATCH_GROUP（専用グループ）/ WATCH_CONFIG を書き換えて：
sudo install -m 644 zee-cutd.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now zee-cutd
cd / && sudo env PYTHONPATH=/opt/zee/src /usr/bin/python3 -P -s -m zee privsep bootstrap-key \
  --key-id phone --public-key /絶対パス/pub.pem
```

NetworkManager を使う機械では、業務ユーザーが `nmcli networking on` を許されていないか（polkit）も確かめる。

## 4. 業務ユーザー側で使い始める

1. `zee watch` を起動し直す。`zee privsep status` で `"ok": true`・`findings` が空であることを見る。
2. 自動遮断を使う場合だけ、署名付きで ON にする：
   ```sh
   zee privsep challenge auto_set state=on > req.json      # 照合コード（2桁）がこの画面に出る
   # 承認端末側（秘密鍵のある機械）で：
   zee privsep digest --request req.json --entered <照合コード> --out d.bin
   #   → 承認する中身（op・args・host・aud・期限）が表示される。**op と args が自分の頼んだものか確かめてから** yes と打つ
   openssl pkeyutl -sign -inkey k.pem -in d.bin -out sig.der
   # この機械に戻って（5分以内）：
   zee privsep submit --request req.json --entered <照合コード> --key-id phone --signature sig.der
   ```
   復旧・設定の差し替え・自己防衛の ON（`tamper_set action=egress|full`）・停止も同じ3段。
   署名付きの操作が1つ実行されると、それより前に出した未使用の請求はすべて無効になる（新しく challenge からやり直す）。
3. **自己防衛（`tamper_set`）を ON にする前に**：ON の間は、業務ユーザーの assets.toml を書き換えてから
   `config_set` が承認されるまでの間や、`zee watch` を 300 秒以上止めた時（更新・再起動を含む）にも遮断しうる。
   設定を変える・watch を止める時は、先に `tamper_set action=off` を承認しておく。

## 5. 戻し方（順序を守る）

1. 遮断中なら：`challenge restore asset_id=<資産> scope=recorded` に署名して復旧し、通信が戻ったことを確かめる。
2. 署名付き `stop`。署名できない時は root で `sudo launchctl bootout system/io.github.kamanoi.zee-cutd`
   ／`sudo systemctl disable --now zee-cutd`。
3. 業務ユーザーの assets.toml から `[privsep]` を外し、`zee watch` を起動し直す（従来の遮断に戻る）。
4. plist／unit・状態ディレクトリ・コードは `mv` で退避する（削除しない）。
5. 遮断部が起動できず遮断が残った時：root で `pfctl -a com.apple/zee-egress-cut -F all`（macOS）、
   `nft delete table inet zee_egress`（Linux）など、`docs/design/self-defense.md` §7.2 の 7 の救済を使う。

## 6. 承認端末の鍵をすべて失った時

root で：①遮断部を止める ②`<状態ディレクトリ>/admin_keys.json` を `mv` で退避 ③起動
④ `cd / && sudo env PYTHONPATH=<src> <python3> -P -s -m zee privsep bootstrap-key --key-id phone --public-key /絶対パス/pub.pem` で登録し直す。

## 7. エラーコード（`zee privsep ...` と遮断部の返答の `code`）

| コード | 意味 | 見ること |
|---|---|---|
| Z710 | 遮断部に接続できない（動いていない・ソケットの権限・返答が壊れている） | macOS：`sudo launchctl print system/io.github.kamanoi.zee-cutd`／Linux：`systemctl status zee-cutd` |
| Z711 | 要求の形が正しくない | コマンドの引数 |
| Z712 | このユーザーは許可されていない（`--allow-uid` に無い、または root 専用の操作） | 実行しているユーザー |
| Z713 | 遮断部が受け付けない要求（復旧・設定変更・停止は署名付きだけ） | challenge／submit を使う |
| Z714 | 署名付きの要求の拒否（期限切れ・照合コード違い・署名不正・再送・未登録の鍵） | 新しい challenge からやり直す |
| Z715 | 方針・引数の検査で拒否（自動遮断 OFF・dry_run・未知の資産など） | `zee privsep status` |
| Z716 | 遮断部の内部エラー、または遮断・復旧がエラーを返した | 遮断部のログ（macOS `/var/log/zee-cutd.log`／Linux `journalctl -u zee-cutd`） |
| Z717 | 署名請求の頻度の上限（1分に10件） | 少し待つ |
| Z718 | 署名は通ったが操作自体が失敗（例：復旧が Z601／Z606） | 返答の `detail` |
| Z719 | `--request`／`--signature`／`--public-key` のファイルが無い・読めない・壊れている | ファイルのパス |
| Z720 | 要求は届いたが返事が無い（実行済みの可能性あり） | `zee privsep status` で unresolved・auto を確かめてから次へ |
