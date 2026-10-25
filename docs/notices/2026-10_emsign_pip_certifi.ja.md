# emSign（eMudhra）証明書事案：端末側の更新のお願い（Zee 利用者向け）

最終更新 2026-10-25 ／ 日本語（English version: not published yet）

## 1. 何が起きたか

2026年10月17日、証明書を発行する事業者 eMudhra（ブランド名 emSign）の**中間CA証明書の秘密鍵が、公開物から復元できる状態だった**ことが公表されました。鍵を持つ者は、本物に見える証明書を自分で作れます。

ブラウザ（Firefox・Chrome など）は配布元が自動で遮断しました。一方、**`pip` は OS が持つ証明書の一覧に加えて `pip` 自身が同梱する `certifi` も読み込みます**。そのため OS 側だけ直しても、`pip` が 26.2.2 より前なら問題の証明書を信じたまま通信します（python.org の案内にある Python 側の説明）。

## 2. Zee との関係（どこまでが対象か）

- **Zee の欠陥ではありません。** Zee が担うのはファイル操作を封じ込める層で、「どの証明書を信じるか」はその外側の層です。
- **Zee 本体は依存パッケージを持ちません**（`pyproject.toml` の `dependencies = []`）。`certifi` が入るのは、**任意の MCP 層（`[mcp]` の追加分）を入れた環境**と、あなたの `pip`・`uv` 自身です。
- つまり対象は次のとおりです。

| あなたの状態 | 更新するもの |
|---|---|
| Zee を `uv tool install` で入れた | **`uv` 本体**（＋OSの証明書ストア） |
| Zee を `git clone` ＋ `pip install -e .` で入れた | **その環境の `pip`**（＋OSの証明書ストア） |
| さらに MCP 層（`pip install -e ".[mcp]"` など）を入れた | 上に加えて **`certifi`** |
| Python で他の作業もしている | その**環境ごと**に `pip`（必要なら `certifi`） |

## 3. 先にやること：OS 側の証明書ストア

`uv self update` も `pip` の入れ直しも**ネットワーク越しに取りに行く**ため、先に端末の信頼ストアを対処してください。

- **macOS / Windows**：OS の更新を適用する（配布元が失効情報を配ります）。
- **Linux**：配布元の `ca-certificates` を更新する（例：`sudo apt update && sudo apt install --only-upgrade ca-certificates` ／ `sudo dnf update ca-certificates`）。
- ブラウザは配布元が自動で遮断済みです（利用者の操作は不要）。

この手順が済むまでは、下の更新も「問題の証明書を信じたまま」行うことになります。**順番が大事です。**

## 4. 更新する版（2026-10-25 時点・一次情報で確認）

| 対象 | 必要な版 | 2026-10-25 時点の最新 |
|---|---|---|
| `pip` | **26.2.2 以上** | 26.2.2 |
| `certifi` | **2026.10.19 以上** | 2026.10.23 |
| `uv` | **0.13.4 以上** | 0.13.5 |

同じ案内では `sigstore` 4.5.1・`conda` 26.9.4・`pixi` 0.82.1 も挙げられています。Zee の導入には使いませんが、同じ端末で使っているなら対象です。

## 5. 手順

### A. `uv tool install` で入れた方

```bash
# 1) uv を更新する（§3 を先に済ませてから）
UV_SYSTEM_CERTS=true uv self update          # macOS / Linux
# Windows PowerShell の場合： $env:UV_SYSTEM_CERTS="true"; uv self update

# 2) 版を確かめる（0.13.4 以上）
uv --version

# 3) Zee を入れ直す（タグは GitHub の Releases 一覧から選ぶ）
#    https://github.com/KAMANOI/zee/releases
uv tool install --force "git+https://github.com/KAMANOI/zee@<タグ>"
```

### B. `git clone` ＋ `pip install -e .` で入れた方

**どの環境を直すかを先に確かめます。**

```bash
# いま有効な環境の場所と Python の版
python -c "import sys; print(sys.prefix); print(sys.version)"
```

その環境を有効にしたまま、順に実行します。1 の URL とハッシュは python.org の案内にあるものです。**更新前の `pip` でも、ハッシュが合わなければ入らないため、安全に入れ直せます。**

```bash
# 1) pip を 26.2.2 に入れ直す（1行で実行）
python -m pip install "pip @ https://files.pythonhosted.org/packages/3f/06/3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/pip-26.2.2-py3-none-any.whl#sha256=fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"

# 2) MCP 層を入れている場合は certifi も更新する
python -m pip install --upgrade certifi

# 3) 版を確かめる
python -m pip --version        # 26.2.2 以上
python -m pip show certifi     # Version: 2026.10.19 以上（入れている場合）
```

> Windows PowerShell でも同じコマンドが使えます（`python` が見つからない場合は `py -m pip ...`）。

**仮想環境は1つずつ直してください。** `pip` は環境ごとに入っているため、1つ直しても他は直りません。

### C. macOS で python.org 版の Python を使っている方

Python の版ごとに同じ作業が要ります。版ごとのパスを指定して B の 1〜3 を実行します。

```bash
/Library/Frameworks/Python.framework/Versions/3.13/bin/python3.13 -m pip install "pip @ https://files.pythonhosted.org/packages/3f/06/3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/pip-26.2.2-py3-none-any.whl#sha256=fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"
/Library/Frameworks/Python.framework/Versions/3.13/bin/python3.13 -m pip install --upgrade certifi
```

（`3.13` の部分はお使いの版に読み替えます。free-threaded 版は `PythonT.framework` 配下です。）

### D. これから新しく仮想環境を作る方（見落としやすい点）

`python -m venv` で作った環境には、**その Python に同梱された古い `pip`** が入ります。作った直後に B の 1 をもう一度実行してください。古い `pip` のまま最初のインストールを行うと、そこで問題の証明書を信じた通信が発生します。

## 6. Zee 本体の対応

Zee のロックファイル（`uv.lock`）の `certifi` を 2026.10.19 に上げる変更を用意しています（コミット `f4f97a6`・取り込みは未）。これは**開発側の固定版**で、利用者の端末の `pip`・`uv` はこの変更では直りません。上の手順が必要です。

## 7. 出典

- Python 利用者向けの案内（python.org のディスカッション）: https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576
- 事案の公開ページ: https://emudhra.we-have-a-problem.com/
- Mozilla の審議: https://bugzilla.mozilla.org/show_bug.cgi?id=2083449
- `pip` 26.2.2 の配布物の sha256：PyPI の公開情報を 2026-10-25 に取得し、上のコマンドのハッシュと一致することを確認

## 8. この案内で確かめていないこと

- あなたの端末に問題の証明書が実際に残っているか（端末ごとに異なります）。
- Zee が必要とする Python は 3.11 以上（`requires-python = ">=3.11"`）で、**動作確認の範囲は 3.11・3.12・3.13** です。各配布元（Homebrew・公式インストーラ・ディストリビューション）の修正の出方までは確認していません。
- `sigstore`・`conda`・`pixi` を使う環境での具体的な手順（上記の版だけを記載しています）。
