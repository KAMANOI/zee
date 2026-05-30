# Zee

> 🌐 English: [README.en.md](./README.en.md) ｜ 🌐 LP: https://kamanoi.github.io/zee/

> Zee は、高度AI時代において、防御準備が追いついていない組織や個人が、最初の一歩を踏み出すためのオープンプロジェクトです。

```
Project Status:
Early Public / Research Project

Zee is not a production-ready security product.

Zee does not currently guarantee protection, containment, prevention of data theft, or detection effectiveness.

This repository currently provides architecture, research direction, preparation guidance, and experimental concepts under active development.
```

---

## なぜ Zee があるのか

社会の不安を減らしたい。これが Zee の出発点です。

AI は素晴らしい技術です。しかし攻撃側もそれを使えます。問題は AI そのものではなく、社会の準備が追いついていないこと。

守りたいのは、安心して暮らせる社会、人と人の信頼、まじめな企業の努力、善意が無意味にならないこと。Zee が有名になることが成功ではありません。社会が安定すれば成功です。誰かがより良い方法を作るなら、それでも良いと考えています。

---

## Mythos 時代の備え

機械の速度で動く攻撃が現れました。脆弱性の発見と武器化が、安く・速く・大量になっています。

以下はいずれも AI を開発する Anthropic 自身が公表した数字です。

- 旧世代モデルが数百回中わずか 2 回しか攻撃コードに仕立てられなかったブラウザ（Firefox の JavaScript エンジン）の脆弱性を、新世代モデルは **181 回** 動作する攻撃コードに変えた
- **27 年間**、専門家監査と自動テストを生き延びた OpenBSD の欠陥を、**約 1,000 回の自動試行・総額 2 万ドル未満** で発見した
- 横断的な調査では **23,000 件超** の脆弱性が見つかり、約 **50 億台** の機器に影響する暗号ライブラリの致命的欠陥（CVE-2026-5194）もこの流れで発見された

出典：Anthropic Red Team（[red.anthropic.com](https://red.anthropic.com/)）／ Project Glasswing

これらは **攻撃側の能力** を示す数字です。Zee はそれを止める道具ではありません。
Zee が向き合っているのは、**攻撃能力の進化速度** と **防御準備の普及速度** の差です。Zee は、その差を少しでも埋めることを目指します。

---

## Zee とは何か

「侵入されるな」ではなく **「盗まれるな」** を出発点にしています。さらに言えば **「時間を稼ぐ」** ——本職の対策や対応が届くまでの猶予を増やすことを目指します。

これは現時点での **設計目標** であり、まだ測定・実証済みの性能主張ではないことを最初に明記します。

**Zee ではないもの：**
- AI を倒すプロジェクトではない
- 国家サイバー兵器ではない
- 完全防御システムではない
- アフィンコラッツの普及活動ではない

**Zee の目的：** 防御ゼロ状態を減らすこと。

---

## Zee でできること

現段階の Zee が提供するのは、以下です。

- **Starter Guide** — 何から考え始めればよいかの最初の一歩（[STARTER_GUIDE.md](./STARTER_GUIDE.md)）
- **事業者向けガイド** — 次世代AIの脅威に不安を感じる事業者向け・専門用語ゼロ・併用すべき防御策と相談先まで案内（[business_guide.html](https://kamanoi.github.io/zee/business_guide.html)）
- **Architecture 概要** — 設計の意図と各構成要素の役割（[ARCHITECTURE.md](./ARCHITECTURE.md)）
- **Research note** — 研究方向としての CDS とアフィンコラッツ研究（[RESEARCH.md](./RESEARCH.md)）
- **MVP 実装** — 軽量な囮トリップワイヤ＋自動封じ込め（`src/zee/`・**既定 dry_run**）

---

## MVP — 動く囮トリップワイヤ

`src/zee/` に MVP の実装があります。**既定では dry_run で動き、実際の遮断は行いません。** 資産プロファイルで `response_mode: auto` を明示し `dry_run: false` にしたときだけ、自動遮断（contain）が走ります。

### インストール

```bash
git clone https://github.com/KAMANOI/zee.git
cd zee
pip install -e .
```

### 起動

```bash
# 1. 資産プロファイルを作成
cp examples/assets.example.yaml ./assets.yaml
# 編集して decoy_paths を自組織のパスに置き換える

# 2. 監視開始（既定は dry_run、実遮断なし）
zee watch -c ./assets.yaml

# 3. 別ウィンドウで「攻撃者として」囮を読んでみる
cat ~/.aws/credentials.decoy   # この瞬間 zee が高信頼イベントを記録
```

### このフェーズの Zee がすること／しないこと

**すること**：
- 囮ファイルを設置・登録する
- 囮への接触（OS の検知能力に応じて open / read / modify）を高信頼イベントとして検知する
- ローカル通知＋（任意で）webhook を出す
- `response_mode: auto` の資産では、`dry_run: false` のときのみ自動遮断する
- すべてを計測する（検知レイテンシ・遮断完了時刻・誤検知マーカー）

**しないこと**：
- 侵入そのものの防御（入口防御の役割・置き換えない）
- ヒューリスティック検知での自動遮断（高信頼の囮接触のみ）
- 自動再接続（復旧は手動：`zee restore <asset_id>`）

### 検知能力マトリクス

`zee capability` で出力できます。実装の現在地：

| OS | Backend | open | read | modify | canary fallback | status |
|---|---|---|---|---|---|---|
| Linux | inotify | yes | yes | yes | no | implemented |
| macOS | kqueue + canary | no | no | yes | yes | implemented |
| Windows | ReadDirectoryChangesW + canary | no | no | yes | yes | implemented (Windows 実機未検証) |

- **Linux** — `inotify` で open / read / modify を直接観察します（標準ライブラリのみ・ctypes 経由）
- **macOS** — `kqueue/EVFILT_VNODE` で変更系のみ観察します。read 検知は OS の制約（Endpoint Security framework が必要）で直接できないため、囮ファイルに埋め込んだ canary URL で補います
- **Windows** — `ReadDirectoryChangesW` で親ディレクトリの変更系のみ観察します。read 検知は SACL + Object Access 監査が必要で、v1 では canary URL に委譲します

Mac で動作検証済み。Linux はコード上完成、実機での連続稼働検証は未実施。Windows は実装あり、Windows ハードウェアでの実機検証は未実施。

---

## Limitations — Zee がやらないこと

Zee は誠実に範囲を区切ります。

- **侵入そのものは防がない** — 入口防御（ファイアウォール・EDR・パッチ）の役割を置き換えるものではありません
- **検知中心** — 自動の封じ込め機構は、資産プロファイルで `response_mode: auto` を明示し `dry_run: false` にしたときだけ動きます。既定は dry_run（観測のみ）
- **限界がある** — 機械の速度で動く相手や、ごく小さく具体的な秘密（単一の API キーなど）の保全は、Zee の範囲を超えます
- **未測定** — 効果はまだ独立に検証されていません。本番運用の前に、ご自身の環境で必ず確認してください

これは床であって天井ではありません。安全だと言う前に、失敗条件を先に書きました。

---

## ライセンス

[MIT License](./LICENSE)。このリポジトリにあるものはすべてオープンです。

---

## 論文

設計の数学的な背景：
**Prime survival in affine Collatz dynamics（v20）**
→ https://github.com/KAMANOI/collatz-prime-survival/blob/main/paper/prime_survival_affine_collatz_v20.pdf

---

## 支援

Zee は無料です。もし役に立ったら、GitHub Sponsors からの支援を歓迎します。

---

## 免責

- Zee は現在 **Early Public / Research Project** の段階です
- Zee は **万能ではありません** — 侵入そのものを防ぐものでも、すべての攻撃を検知できるものでもありません
- 機械速度の攻撃能力は進化を続けます。新世代モデルが広く使えるようになる局面では、**Zee 自体の脆弱性チェックとパッチ適用が必要** になります
- Zee は入口防御・修正運用を **置き換えるものではなく、補完する一層** です
