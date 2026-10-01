# Zee containment demo (recording environment)

> **前提のズレ（冒頭に明記）**：この demo は、先行指示書「封じ込め証跡の報告用エクスポート」（`zee export`）が完成・コミット済みであることを前提にしていなかった。実際は E403（60分タイムアウト）で**未コミット**（`feat/containment-report-export` ブランチの作業ツリーに差分が残るのみ）。本 demo は証跡出力に依存しない範囲（収録環境・模擬スクリプト・封じ込め動作そのものの収録）までを完成させ、証跡付き出力画面の収録は `zee export` のコミット後に別途行う（詳細は本ファイル末尾「証跡出力について」）。
>
> もう一点、指示書は隔離環境として「ローカルの使い捨てVM、またはDockerコンテナ」を想定していたが、本機にはどちらも未インストールで、新規導入は資源制約上避けた（詳細は次節「隔離環境の選定」）。Zee 自身が使う `sandbox-exec` 技術で代替している。

**これは実際のランサムウェアではありません。** `mock_attacker.py` は、Zee の囮トリップワイヤ＋封じ込めが反応する様子をカメラの前で再現するためだけに作った、学習・実演用のダミー改ざんスクリプトです。同梱のダミーディレクトリ以外には一切触れません。

用途：HDR の YouTube 向け縦型ショート動画・X 投稿・note 記事のスクリーンショット素材。検証可能性（第三者が自分で再現して確かめられるか）は別タスク（GitHub Actions での自動公開テスト）の範囲で、本ディレクトリは「収録用の再現環境」までを提供します。

## これは何をするか

1. 使い捨てのサンドボックスディレクトリに、偽の「書類」ファイルを作る（`make_dummy_files.py`）
2. そのディレクトリを対象に Zee の囮を仕込んで監視を始める（`zee watch`、**既定どおり dry_run**）
3. 隔離した状態で模擬攻撃スクリプトを走らせ、ファイルの上書き・暗号化を模した書き潰し・拡張子変更を伴うリネームを行う（`mock_attacker.py`、サンドボックス外には一切触れない・ネットワーク通信なし）
4. Zee が囮への改ざんを検知し、通知を出し、「封じ込め（ネットワーク遮断）を行うところだった」ことを dry_run のまま記録する様子を `zee watch` のログと `zee status` で確認する

`demo/run_demo.sh` がこの一連の流れを自動化します。

## 隔離環境の選定（Phase 0・技術判断）

タスクの指示は「ローカルの使い捨て VM、または Docker コンテナ」から選ぶことだったが、**このマシンには Docker も VM 関連ツール（Docker/limactl/multipass/vagrant/qemu/UTM/colima/podman）も一切インストールされていない**ことを確認した（2026-10-01実機確認）。加えてこのマシンは物理メモリ 8GB で、確認時点の空き物理メモリは実測 約116MB（`vm_stat`）と極めて逼迫している（過去の調査 memory: kamanoi-mac-8gb-ram-local-llm-limit と同型の制約）。この状態で新規に Docker Desktop や VM ハイポケーターを導入するのは、システムの不安定化リスクと新規重量級ソフトのインストールという二重のコストがあり、収録環境構築という目的に対して釣り合わない。

**選定：macOS 標準の `sandbox-exec`（Seatbelt）** による隔離を採用した。理由：

- Zee 自身が「危険なものを安全に実行する」というまったく同じ目的のために、入口ゲートの振る舞いサンドボックス（`src/zee/gate/sandbox/`）で既にこの技術を使っている（ponytail ルール：既存コードベースにある手法の再利用）。zero-install（macOS 標準搭載）・追加の RAM 消費なし。
- `demo/sandbox.sb` に、deny-default → サンドボックスディレクトリ以外の `/Users` 配下の読み取りを拒否 → 書き込みはサンドボックスディレクトリのみ許可 → ネットワーク全拒否、という Zee 自身のプロファイルと同じパターンの SBPL を書いた（Zee のコードコメントにある「sandbox-exec は解決済みパスにマッチする」「SBPL は最後にマッチしたルールが勝つ」という既知の落とし穴もそのまま踏襲）。
- 実機で3点とも確認済み（2026-10-01）：①サンドボックス外（`/tmp`）への書き込み → `PermissionError`で拒否 ②実ホームの dotfile（`~/.zshrc`）の読み取り → `PermissionError`で拒否 ③ネットワーク接続（`socket.create_connection`）→ `PermissionError`で拒否。

Docker/VM が将来インストールされた場合、`demo/sandbox.sb` を Docker 実行に置き換えるのは容易（Zee 自身の `IsolationBackend` も同じ理由で「機能ベースのインターフェースにしてある」とコメントされている）。

## 封じ込め（containment）の見せ方について — 重要な事実確認

Zee の実際の「封じ込め」は、**書き込み操作そのものを止める機能ではない**。README / ARCHITECTURE で確認した実際の動作は：

1. 囮ファイルへの「変更系」接触（書き込み・削除・リネーム・拡張）を検知する
2. ローカル通知を出す（＋任意で webhook）
3. 資産プロファイルで `response_mode: auto` を明示し `dry_run: false` のときだけ、**OS レベルでネットワーク（インターフェース全体 or egress のみ）を遮断する**（`src/zee/responder/cut_full.py` / `cut_egress.py`。`pfctl`/`iptables`/`ifconfig` 等を呼ぶ・要管理者権限）

つまり Zee は「ファイルが書き換えられるのを防ぐ」のではなく、「書き換えが起きたことに気づいて、被害（データの持ち出し・横移動）が外に広がる前にネットを切る」設計（README の「時間を稼ぐ」という表現と一致）。

このため、**指示書内の例示フレーズ「勝手にファイルを書き換える動きを、その場で止めます」は Zee の実際の動作と一致せず、過剰主張になる**。`RECORDING_GUIDE.md` では事実と一致する代替フレーズ案を出している。

### 実際の封じ込め（ネットワーク遮断）を本当に実行する収録はしていない

`cut_full`/`cut_egress` は実機の `pfctl`/`ifconfig`/`iptables` を呼び、**収録に使っているこの Mac の本物のネットワークを本当に切断する**（要 sudo）。これを収録機で直接実行するのは危険（インターネット接続が本当に切れる・復旧も手動）であり、かつ安全に動かすには本物の使い捨て VM/コンテナが要るが、前述のとおりこのマシンには用意できなかった。

そのため本番の demo は **`response_mode = "auto"` のまま `dry_run = true`**（Zee 自身の安全な既定）で動かし、「封じ込めを実行するところだった（would_cut=yes）」ことをログと通知で見せる構成にしている。実機確認済み（下記）。本物のネットワーク遮断を見せる収録は、別途 VM/コンテナ環境を用意した上での追加タスクとする（末尾の PENDING 参照）。

## 実機確認結果（2026-10-01）

`demo/run_demo.sh` をこのリポジトリの committed コード（HEAD, `40d645e`）から作った別 venv で実行し、以下を確認した：

- `zee watch`（`dry_run=true` / `response_mode=auto`）がサンドボックス内に囮（`aws-credentials.decoy` / `.env`）を自動設置
- `mock_attacker.py`（`sandbox-exec` 隔離下）がサンドボックス内の全ファイル（偽の書類6点＋囮2点）を書き潰し→`.locked`にリネーム、を2周実行
- `zee watch` のログに `[event] decoy write+extend+rename → mode=contain cut=no would_cut=yes` 等、change-class の接触すべてで `mode=contain` ・ `would_cut=yes` ・ `cut=no`（実遮断なし）を確認
- `zee status` で `cut state: clear`（実際には何も遮断されていない）と `burst activity: ⚠ 1 burst(s) detected`（5 change-class events within 300s）を確認
- macOS のデスクトップ通知（`display notification`）が検知のたびに発火することを確認（録画で画面に残る）

## 使い方

```bash
# このディレクトリ（zee リポジトリのルート）で、初回のみ
uv venv .venv-demo --python 3.12
source .venv-demo/bin/activate
uv pip install -e .

# 収録本番
source .venv-demo/bin/activate
demo/run_demo.sh
# 「Enter を押すと模擬攻撃を実行します」で止まるので、ここで画面収録を開始してから Enter
```

実行のたびに `demo/.run/<timestamp>/` に使い捨てのサンドボックスと assets.toml とログができる（`.gitignore` 済み・中身は偽ファイルのみ・そのまま破棄して問題ない）。

## 証跡出力（`zee export`）について — 未実施

先行指示書「20261001-0001」（封じ込め証跡の報告用エクスポート）は、2026-10-01 時点でタイムアウト（E403・60分）により**未コミット**（`feat/containment-report-export` ブランチの作業ツリーに差分が残っているのみ・コミットなし）。本タスクはこの機能に依存しない範囲（収録環境・模擬スクリプト・封じ込め動作の収録）までを完成させた。**証跡付き出力画面の収録は、`zee export` がコミットされてから別途行う。**

## 触れていないもの

- Zee 本体のコード（`src/zee/`）には一切手を入れていない
- `feat/containment-report-export` ブランチの未コミット作業（README.md・cli.py・errors.py・mcp/server.py・telemetry/events_log.py の変更、新規 report_export.py 等）には一切触れていない。本デモは `git worktree add` で作った別ディレクトリ（committed HEAD 40d645e から分岐した新ブランチ `demo/containment-showcase`）で作業した
