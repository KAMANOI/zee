# 設計：AIエージェントの道具と封じ込め設定を見る入口審査の検査項目（G205〜G211・G602）

状態：v0.16.0 に収録（開発時の枝 `feat/agent-config-checks-20261019`）。
出典：Anthropic 公式 `claude-quickstarts`（MIT、main `9ec32b9`）の精読。**コードは持ち込まず、
検査項目と試験用の入力を自作した**（試験の「危ない書き方」は本リポジトリで書いた短い文字列で、
上流のコードの写しではない）。

## 1. 着手前の一覧：候補 a〜g が Zee に既にあるか

読んだもの：`src/zee/gate/static_checks.py`（G2xx〜G7xx）、`adapters.py`、`denylist.py`、
`gate/sandbox/`（第2段＝`--behavioral`、G8xx）、`docs/gate.md`、隔離側（`egress/`・`responder/`・
`docs/design/privsep.md`・`egress-approval.md`）。

| 候補 | 内容 | 着手前の状態 | 追加したコード |
|---|---|---|---|
| a | 出力を引用符で囲まずシェルへ渡す | **無い**（G202 は「サブプロセスを起動する」と言うだけで、引数の作り方は見ない） | G205 |
| b | 画面/ブラウザ操作の道具を自前定義で宣言 | **無い** | G206（LOW） |
| c | 道具の定義と実装の引数のずれ | **無い** | G207（LOW） |
| d | 許可リストに、自分で書けるスクリプト・任意コード実行が入る | **無い** | G208 |
| e | 通信制限が記録モードのまま／ワイルドカード | **無い**（Zee の egress 側は自分の遮断を作る部分で、他人の設定は読まない） | G209 |
| f | 秘密ファイルの中身を読む手順 | **一部**：G601 は「秘密のパスに触れる」言及を MEDIUM で拾う。*中身を読む手順*と*存在確認だけの手順*は区別できない | G602（読む手順だけ。`-q/-c/-l`・「never/do not」は除く） |
| g | パスワード無し sudo・画面共有 | **無い**（`gate/sandbox/decoys.py` に `.env` の囮はあるが設定は見ない） | G210・G211 |

第2段（`--behavioral`）は install hook を隔離して動かす仕組みで、設定の良し悪しは見ない。今回の項目は
すべて**第1段（静的）**に足した。第2段・封じ込めの挙動は変えていない。

## 2. 何を検出するか（実装の要点）

実装：`src/zee/gate/agent_config.py`。`static_checks.scan_tree` の最後に呼ぶ（1コード・1ファイルにつき1件）。
標準ライブラリのみ。何も実行しない。Python は `ast`、他は1行ずつの有界な正規表現（行は2000字で切る）。

- **G205**：`os.system` / `shell=True` / `create_subprocess_shell` と、それに引数を渡す関数（名前で追跡、
  複数ファイル・多段）に、f文字列・`.format`・`%`・`+` で作った文字列が届く。`shlex.quote`・`int()`・`{x:d}`・
  大文字定数は除く。コマンドを `list` に溜めて `" ".join` する書き方も追う。JS/TS は `child_process` を使う
  ファイルの `exec`/`execSync` にテンプレートリテラル／`+` で値が入る場合。
- **G206**：`name: "computer"`（または browser）＋ `input_schema` があり、公式の型（`computer_20…`）が無い。
  API 側の画面操作向けの安全判定（画面上の仕込み指示の検出）は自前定義には効かない、と公式 README が
  書いている（`computer-use-best-practices/README.md` 291〜295行）。LOW（警告）。`tests/` 配下は除く。
- **G207**：クラス内のリテラル `input_schema` の `properties`/`required` と、`execute`/`__call__`/`run` 等の
  引数を突き合わせる（宣言したのに受けない／受けるのに宣言しない／required なのに既定値あり）。`**kwargs`
  受けと `validates_own_input` は除く。
- **G208**：`allow`/`whitelist` を名前に含む Python・JS の一覧、Claude の `permissions.allow` の
  `Bash(...)` 規則に、`bash sh python node env sudo eval npx` 等、単独の `*.sh`、`node -e`/`python -c`
  が入る。エージェントが書いたスクリプト・コードがそのまま通る。
- **G209**：`endpoints`/`egress`/`allowed_hosts` 等を含む YAML/JSON/TOML で、`enforcement: audit`（記録して
  通す）・`enforce: false`・ホストの `*`・全経路（`/**`）の許可。経路の*途中*のワイルドカード
  （`/work/*/heartbeat`）は流さない。
- **G210/G211/G602**：`NOPASSWD`、`x11vnc` を起動オプション付きで（パスワード系オプション無しで）起動・
  `-nopw`・`-SecurityTypes None`（apt の導入行は除く）、秘密ファイルを `cat/head/grep` する手順。

### 実物での確認（2026-10-19、`claude-quickstarts` main `9ec32b9` の全 648 ファイルを検査、0.9 秒）

| 実物 | 結果 |
|---|---|
| `computer-use-demo/.../computer.py`：`key -- {text}`（167行）等 | G205 で検出（list→join→helper→`create_subprocess_shell` の4段を追跡）。同ファイルの `shlex.quote(chunk)` は除外 |
| `computer-use-demo/.../edit.py`：`find {path}` | G205 |
| `autonomous-coding/security.py`：許可リストに `node`・`init.sh` | G208 |
| `computer-use-demo/Dockerfile`：`NOPASSWD: ALL`／`x11vnc_startup.sh`：`-nopw`／`computer-toolset/README.md`：`-SecurityTypes None` | G210／G211 |
| `computer-use-best-practices/.../computer.py`：`name="computer"`（自前の定義） | G206（LOW） |
| 封じ込めの良い型：`openshell/policy.yaml`（`enforcement: enforce`、`landlock: hard_requirement`）／`first-run/SKILL.md`（「`.env` を読まない」）／`setup-skill.md`（`grep -c … .env`） | **検出なし**（誤検出を調整済み。調整前は `grep -c`・`more than`・apt の導入行で誤検出した） |

**指示書とのずれ（確認した事実）**：指示書は OpenShell の policy.yaml を「経路にワイルドカードを使わない」と
書いたが、実物には `/v1/environments/ENVIRONMENT_ID/work/*/heartbeat` がある（ファイル内のコメントも
「work ID は wildcard のまま」と説明している）。セッション ID は埋め込まれ、作業 ID だけがワイルドカード。
このため G209 は「経路の途中のワイルドカード」を流し、ホストの `*` と全経路許可だけを拾う。
実物で確認できた他の記述：`sandbox/default.sb` はネットワーク全拒否（`deny network*`）で `~/.ssh`・`~/.aws`・`.env`
等の読み取りを拒否、`tools/shell.py` は 30 秒で打ち切り（`_TIMEOUT_S = 30`）、`tools/base.py` は import 時に
定義と実装の引数のずれを検出、`mcp-server-typescript/src/tools.ts` は道具の登録時に対象 ID の宣言が無ければ
例外を投げる。**未確認**：出力の「64KB」は設定値（`max_shell_output_bytes`）で、既定値は読んでいない。
`openshell-prover` は2つの方針の包含を調べ、範囲外なら終了コード 1、決められなければ 3（README で確認、
実行はしていない）。

### 限界（言い切り）

ヒューリスティックで、完全な検出ではない（不変条件 I5）。「値が上流で検証されているか」は見えないので、
検証済みでも報告する。ファイルをまたぐ追跡は関数名だけ。JS/TS の引数の突き合わせ（G207）と、
リテラルでないスキーマは見ない。コマンド許可リストの変数名が `allow` を含まなければ G208 は見ない。
難読化した設定は見えない。これらは「見るべき場所の目印」であって安全の証明ではない。

## 3. 封じ込めの良い型 × Zee の封じ込めモデル（比較表）

実装はしない（比較と判断だけ）。参照した Zee 側の事実：`privsep.md` §6（業務側 `assets.toml` のバイト列
SHA-256 が承認済みの写しと違えば所見）、`cut_full.py`・`restore.py`（遮断・復旧のあと OS の状態を読み直す）、
`egress-approval.md`（許可リスト外への送信は署名が出るまで保留）、`privsep.md` §5（承認は端末側の署名、
遮断部は公開鍵のみ）、Zee 本体は実在の鍵を持たず囮（偽の値）を置く設計。

| 良い型（相手側の実装） | Zee の現状 | 取り込むと | 費用（工数は**推定**） | 価値 | 判断 |
|---|---|---|---|---|---|
| **A. 設定と基準ファイルのずれ検査**（`openshell-prover`：実際の方針が基準の範囲を超えれば終了コード 1、決められなければ 3） | **一部ある**：Zee 自身の設定はバイト列ハッシュで見張る。遮断後の OS 状態の読み直しもある。**無い**：「いま実際に効いている送信規則が、承認済みの許可の範囲を超えていないか」の意味での照合 | `zee doctor` に読み取り専用の項目（Zee の pf アンカー／nft の実状態が、承認済み許可リストから描いた規則と一致するか）を足す軽い版が現実的。prover 相当の「範囲包含の証明」は規則の文法ごとの実装になり大きい | 軽い版：OS別（macOS/Linux）で約2〜3日。Windows は実機未検証のため対象外。包含証明版：約2〜3週（根拠なしの推定） | 中：Zee 自身が規則を作るので「ずれ」は主に手作業・他ソフトによる書き換え。起きる頻度は**情報なし**（計測していない） | **軽い版を推奨（承認が要る場合のみ）**。重い版は見送り |
| **B. 送り先と位置を限った鍵の差し替え**（偽の値だけを見せ、許可した送り先・ヘッダ/本文でだけ本物に差し替え。相手の実装は Anthropic の vault が出口で差し替える） | **無い**。ただし「偽の値だけを見せる」は Zee の囮と同じ考え方 | 差し替えには出口で通信を読み書きする中継（プロキシ）が要り、Zee が本物の鍵を預かる側になる | 中継の新設＋鍵の保管：約1〜2か月、かつ新しい攻撃面（推定） | 低〜負：「データは持たない・残さない」「Zee は本物の鍵を持たない」「入口防御ではない」（目的カード (b)）に反する。差し替えは相手側のプラットフォーム機能で、Zee が真似る場所ではない | **取り込まない**（鍵の扱いは利用者のプラットフォーム側の機能に任せ、Zee は囮で検知に徹する） |
| **C. 鍵の3段分離**（組織鍵／環境鍵／セッション専用の短命トークンを分け、サンドボックスには最下段だけを標準入力で渡し、上位の鍵は起動時に消す） | **一部ある**（Zee 自身の承認は端末側の署名で、遮断部が持つのは公開鍵のみ）。**無い**：利用者のエージェント環境がこの分離をしているかを見る目 | 入口審査に項目を1つ足す（例：Dockerfile・compose・起動スクリプトで `ANTHROPIC_API_KEY` 等の組織級の鍵をそのままコンテナ環境変数に渡している）。設計の助言は文書化 | 検査項目1つ＋試験：約0.5〜1日。文書：約0.5日（推定） | 中：G602/G208 と同じ型で、実物の誤用（鍵を丸ごと渡す）を拾える。誤検出（環境変数名の一般性）は試験で詰める必要あり | **検査項目として足す価値あり**（承認が要る場合のみ。設定の*作り方*の助言文書は別） |

**費用の根拠**：工数はすべて推定（Zee の既存コードの規模と作業量からの見立てで、実測ではない）。有料の導入は
無い（標準ライブラリのみ・追加費用0円）。

## 4. 今後の検討項目

- 上の A（軽い版）と C は将来の候補。B は取り込まない。
- v0.16.0 に入るのは G205〜G211・G602 だけで、封じ込めの挙動は変わらない。
