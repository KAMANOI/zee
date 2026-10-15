# 手順書：権限分離（root の遮断部）を入れる・戻す — 試作・既定オフ

設計：`docs/design/privsep.md`。**この手順はどれも代表の開発機で実行していない。** 使い捨ての VM か、
GitHub Actions（`.github/workflows/privsep.yml`）で同じ確認が通ってから、実機に入れるかを決める。
root の操作を含むので、実行するのは機械の正当な所有者だけ。下の `<業務ユーザー>` は `zee watch` を動かすユーザー。

## 0. 先に用意するもの

- 承認端末の P-256 鍵。試作では openssl で作った鍵（`openssl ecparam -name prime256v1 -genkey -noout -out k.pem`、
  公開鍵は `openssl ec -in k.pem -pubout -out pub.pem`）。**秘密鍵はこの機械に置かない**（別の端末・別の機械で署名する）。
- root 所有の Python 3.11 以上（macOS の Homebrew の Python は業務ユーザーの所有なので**使わない**。root 所有の場所に入れた Python を使う）。

## 1. macOS（LaunchDaemon）

```sh
Z="/Library/Application Support/Zee"
sudo mkdir -p "$Z" && sudo cp -R src "$Z/" && sudo chown -R root:wheel "$Z" && sudo chmod -R go-w "$Z"
sudo install -d -m 700 -o root -g wheel "$Z/cutd"
sudo install -m 600 -o root -g wheel <業務ユーザーの assets.toml> "$Z/cutd/assets.toml"
# examples/privsep/io.github.kamanoi.zee-cutd.plist の PYTHON_BIN / WATCH_UID（id -u <業務ユーザー>）/
# WATCH_GROUP（id -g <業務ユーザー>）/ WATCH_CONFIG（業務ユーザーの assets.toml の絶対パス）を書き換えて：
sudo install -m 644 -o root -g wheel io.github.kamanoi.zee-cutd.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/io.github.kamanoi.zee-cutd.plist
sudo env PYTHONPATH="$Z/src" <root 所有の python3> -m zee privsep bootstrap-key --key-id phone --public-key pub.pem
```

## 2. Linux（systemd）

```sh
sudo mkdir -p /opt/zee && sudo cp -R src /opt/zee/ && sudo chown -R root:root /opt/zee && sudo chmod -R go-w /opt/zee
sudo install -d -m 700 /var/lib/zee-cutd
sudo install -m 600 <業務ユーザーの assets.toml> /var/lib/zee-cutd/assets.toml
# examples/privsep/zee-cutd.service の WATCH_UID / WATCH_GROUP / WATCH_CONFIG を書き換えて：
sudo install -m 644 zee-cutd.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now zee-cutd
sudo env PYTHONPATH=/opt/zee/src /usr/bin/python3 -m zee privsep bootstrap-key --key-id phone --public-key pub.pem
```

NetworkManager を使う機械では、業務ユーザーが `nmcli networking on` を許されていないか（polkit）も確かめる。

## 3. 業務ユーザー側

1. 業務ユーザーの assets.toml に次を足す。**足した後のファイルを §1／§2 の承認済みの写しにする**（違うと `watch_config_unapproved`）。
   ```toml
   [privsep]
   socket = "/var/run/zee/cutd.sock"   # Linux の unit の既定は /run/zee/cutd.sock
   ```
2. `zee watch` を起動し直す。`zee privsep status` で `"ok": true`・`findings` が空であることを見る。
3. 自動遮断を使う場合だけ、署名付きで ON にする：
   ```sh
   zee privsep challenge auto_set state=on > req.json      # 照合コード（2桁）が画面に出る
   # 承認端末側（秘密鍵のある機械）で：
   zee privsep digest --request req.json --entered <照合コード> --out d.bin
   openssl pkeyutl -sign -inkey k.pem -in d.bin -out sig.der
   # この機械に戻って（5分以内）：
   zee privsep submit --request req.json --entered <照合コード> --key-id phone --signature sig.der
   ```
   復旧・設定の差し替え・自己防衛の ON（`tamper_set action=egress|full`）・停止も同じ3段。

## 4. 戻し方（順序を守る）

1. 遮断中なら：`challenge restore asset_id=<資産> scope=recorded` に署名して復旧し、通信が戻ったことを確かめる。
2. 署名付き `stop`。署名できない時は root で `sudo launchctl bootout system/io.github.kamanoi.zee-cutd`
   ／`sudo systemctl disable --now zee-cutd`。
3. 業務ユーザーの assets.toml から `[privsep]` を外し、`zee watch` を起動し直す（従来の遮断に戻る）。
4. plist／unit・状態ディレクトリ・コードは `mv` で退避する（削除しない）。
5. 遮断部が起動できず遮断が残った時：root で `pfctl -a com.apple/zee-egress-cut -F all`（macOS）、
   `nft delete table inet zee_egress`（Linux）など、`docs/design/self-defense.md` §7.2 の 7 の救済を使う。

## 5. 承認端末の鍵をすべて失った時

root で：①遮断部を止める ②`<状態ディレクトリ>/admin_keys.json` を `mv` で退避 ③起動 ④`bootstrap-key` で登録し直す。
