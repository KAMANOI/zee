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

詳細な研究ノート本文（Research question / What CDS is not / Honest comparison / Status の 4 段構成）は、現時点では英語のみ公開しています：[RESEARCH.en.md](./RESEARCH.en.md) の "Collatz Deception System (CDS) — Research Note" を参照してください。日本語訳は後日追加予定です。

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
