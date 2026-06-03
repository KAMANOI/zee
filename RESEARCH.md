# Zee — Research

> 🌐 English: [RESEARCH.en.md](./RESEARCH.en.md)

このドキュメントは Zee の **研究方向（research direction）** を扱います。
研究は研究として記述します。製品の説明でも、効果の主張でもありません。

```
Status: Research-stage
Experimental. Intended architecture. Validation pending.
```

---

## CDS（Collatz Deception System）

```
Collatz Deception System (CDS)
An experimental deception architecture inspired by affine Collatz research.
The effectiveness of CDS has not yet been independently validated.
```

CDS は、Zee の中で **罠多様化（trap diversification）の研究プリミティブ** として位置づけられた、実験的な構成です。
完成済みの防御システムではありません。Research-stage、Experimental、Intended architecture、Validation pending —— このどれかに該当する状態のものを扱います。

---

## CDS — 研究ノート

**研究上の問い。** アフィンコラッツ写像 f(p) = (a*p + b) / c は、安価に計算でき、小さなシードとパラメータ（a, b, c）から再生成可能な整数軌跡の大規模なパラメータファミリーを定義します。その統計的挙動（軌跡の長さ・増減プロファイル・値の分布）は v20 研究でマップタイプを横断して特性評価されています。CDS が調べるのは、セッションごとまたはデプロイごとにパラメータをローテーションすることで欺瞞環境のフィンガープリント化コストが上がるか——攻撃者の分類器が Zee の囮活動を実際のシステム活動から分離するために必要なサンプル数が増えるか——という点です。

**CDS ではないもの。** CDS は暗号学的・セキュリティ的・封じ込め的な保証ではありません。**Collatz 問題の決定不能性は、ここでは防御的な役割を持ちません**：攻撃者は計算が停止するかどうかを判断する必要がなく、CDS は「どの罠も検出不可能または回避不可能だ」とは一切主張しません。アフィンコラッツの出力は構造を持ち、ランダムではありません。十分なサンプルがあればクラスタリングと分類は可能です。パラメータローテーションはフィンガープリント化のコストを引き上げますが、フィンガープリント化を排除するものではありません。

**正直な比較。** 安価・多様・それらしく見える合成アクティビティの生成という限られた目的では、従来の手法（シード付き PRNG・実テレメトリーで学習したマルコフモデル・実ログの摂動再生など）は成熟した代替手段であり、実際のワークロードを模倣するリアリズムの点では多くの場合より強力です。CDS は候補ジェネレーターの一つとして提示しているのであり、推奨される手法ではありません。CDS の潜在的な優位点は、安価・シードから再生成可能（セッションごとの状態が最小）・パラメータから挙動へのマッピングに明示的な理論的理解が伴っている点だけです。

**状態。** Research-stage。Experimental。Intended architecture。CDS の有効性は独立に検証されていません。評価上のオープンクエスチョン：（a）パラメータローテーションが PRNG ベースラインに対して分類器のサンプル必要数を測定可能なほど上げるか；（b）リアリズムのギャップ——分類器が少ないサンプルで CDS テレメトリーを実テレメトリーから分離できるか；（c）セッション 1 つを保持する防御側のコストに対し攻撃者が実際に消費するリソース。これらが測定されるまで、CDS は deployable defense ではなく research direction として読むべきです。

---

## アフィンコラッツ研究

```
Research explores whether affine Collatz dynamics may provide useful trap diversification properties.
This should not be interpreted as a cryptographic, security, or containment guarantee.
```

アフィンコラッツ研究は、罠の多様化（同じ仕掛けに見えにくくする）に役立つ性質を持つかを **オープンクエスチョン** として扱います。
暗号学的保証ではありません。封じ込め保証でもありません。「攻撃者の分類器が、Zee が出す囮の活動を本物の活動から確実に分離するために、より多くのサンプルを必要とするか」を測ることが、評価の中心です。

論文：
**Prime survival in affine Collatz dynamics（v20）**
→ https://github.com/KAMANOI/collatz-prime-survival/blob/main/paper/prime_survival_affine_collatz_v20.pdf

---

## 評価の open question

研究として残っている評価項目（一部）：

- パラメータローテーションが、PRNG ベースラインに対して分類器のサンプル必要数を **測定可能なほど** 上げるか
- リアリズムのギャップ —— 分類器は CDS のテレメトリーを少ないサンプル数で実環境のテレメトリーから分離できるか
- セッション 1 つを保持する防御側のコストに対し、攻撃者が実際に消費するリソースはどれだけか

これらが測定されるまで、CDS は **deployable defense** ではなく **research direction** として読むべきです。

---

## CDS-Full について

CDS-Full は **A. 提言／B. 構想／C. 実装済み／D. 実験中／E. 未実装** が混在する初期段階の構想資料です。読者が混同しないよう、CDS-Full に含まれる各要素は、公開時に上記カテゴリのいずれかを明示する方針です。現状ではこのリポジトリに CDS-Full の本文は含めていません。

---

## 注意

このリポジトリの Research セクションに登場する記述は、すべて以下の前提で読んでください。

- 効果は **独立に検証されていません**
- 「保証」「防げる」「止められる」「不可避」などの表現は、Research にも書かないことを方針にしています
- 実装が **意図する** ことと、実装が **証明している** ことは別物です

研究は、開かれた問いです。

---

→ Zee 全体像については [README.md](./README.md) を参照してください。
