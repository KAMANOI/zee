# Zee — アーキテクチャ概要

> 🌐 English: [ARCHITECTURE.en.md](./ARCHITECTURE.en.md)

```
Project Status:
Early Architecture / Research Preview

This document describes the intended architecture of Zee.

It should not be interpreted as proof that every component is production-ready, independently validated, or suitable for deployment without expert review.
```

---

## 位置づけ

Zee は **侵入後（post-intrusion）** に作動する層を意図して設計されています。
ファイアウォール・EDR・パッチといった入口防御を置き換えるものではなく、それらをすり抜けて内部に到達した相手に対し、**侵入が即座にデータ窃取・運用への被害・気づかれない潜伏に結びつく可能性を下げる** ことを目的とします。

設計思想は「壊れないように作る」から「壊される前提で設計する」へ。これは Zee が新しく作った思想ではなく、現在のセキュリティ分野が広く向かっている方向と一致しています。

---

## 全体の流れ（intended）

```
              ┌─────────────────────────────────────────────┐
              │  正規の業務トラフィック（巻き込まないことを意図）│
              └─────────────────────────────────────────────┘
                              │
   侵入した攻撃者 ──▶ ①ふるまい観察 ──▶ ②番人（安全装置）──▶ 引き込み
                                            │ （誤作動の確率を下げる確定的なゲート）
                                            ▼
                          ┌──────────────────────────────────┐
                          │  実験的な罠環境（research-stage）  │
                          │   ③偽データへのリダイレクト       │
                          │   ④偽内部ネットワーク             │
                          └──────────────────────────────────┘
                                            │
                                            ▼
                                   ⑤長期相関（低速 APT 検知の研究）
```

---

## 各層の役割

| 層 | 役割 | Status |
|---|---|---|
| ① ふるまい観察 | 選ばれたプロセス・ファイル・ネットワークの挙動を観察し、疑わしい逸脱を識別する | Mechanism public |
| ② 番人（安全装置） | 検知と引き込みの間に立ち、確定的なゲートにより誤作動の発生確率を下げる | Mechanism public |
| ③ 偽データへのリダイレクト | 特定の構成において、選ばれたアクセス試行を目印つきの偽データへリダイレクトまたは置換できる | Research-stage |
| ④ 偽内部ネットワーク | 本物そっくりの偽環境で探索のコストと時間を引き上げることを目指す | Research-stage |
| ⑤ 長期相関 | 数ヶ月スパンの潜伏型攻撃を時間をまたいで結びつけて検知する研究方向 | Research-stage |

各 Research-stage 項目は、効果がまだ独立に検証されていません。

---

## 安全性の原則（誤作動の最小化）

侵入後の層で最大のリスクは、正規のプロセスや社員を誤って罠に引き込むことです。Zee はこの risk を **最小化** することを目指します（「ゼロ」は約束しません）。

- 検知と引き込みの間に **二重の安全装置** を置く
- 「誤作動の最小化」と「重大な攻撃の検知」という相反する要件を、1 つの仕組みに詰め込まず **役割を分けて** 両立させる
- 判定は AI の裁量ではなく **確定的なルール** で行う

具体的な作動条件・閾値は実装段階で詰めるパラメータであり、現段階では研究中のものを含みます。

---

## プライバシーの原則

- 生の IP アドレス・個人を特定できる情報は、ログのどの欄にも平文で残さない（保存直前に秘匿・ハッシュ化）
- 蓄積データは期限を過ぎると自動的に削除する
- 相関は「個人」ではなく「セッション（行動の主体）」を軸に行うため、正規ユーザーは分析対象に入らない

これらは設計目標として書いています。実装の各段階で同じ原則が守られているかは、実装側のドキュメントで確認できます。

---

## 依存と配布

- Python の標準機能のみで動作することを設計目標にする（依存を増やさない＝攻撃面を増やさない）
- このリポジトリにある資料はすべて MIT ライセンスのもとで公開します

---

## 研究方向

罠多様化（trap diversification）の研究方向については、別ファイルで扱います：
→ [RESEARCH.md](./RESEARCH.md)

そこに含まれるアフィンコラッツ研究は、**罠の暗号学的保証や封じ込め保証ではなく**、研究上の方向性として記述しています。

---

## 実装の現在地

| 構成要素 | 実装状況 | 場所と備考 |
|---|---|---|
| ① ふるまい観察（囮トリップワイヤ） | ✅ Implemented | `src/zee/watcher/` — Linux は inotify で open/read/modify を直接観察、macOS は kqueue で変更系のみ＋canary フォールバック、Windows は ReadDirectoryChangesW＋canary（Windows 実機未検証） |
| ② 番人（安全装置） | 部分実装 | `src/zee/policy/` — allowlist データ構造実装済み。responder への連結（contain 前に allowlist で降格判定）は次フェーズ。multi-signal trap gate も次フェーズ |
| ③ 偽データへのリダイレクト | Research-stage | 設計のみ。実装は別途検討 |
| ④ 偽内部ネットワーク | Research-stage | 同上 |
| ⑤ 長期相関 | Research-stage | RESEARCH.md（CDS / アフィンコラッツ研究）参照 |
| 応答（自動封じ込め） | ✅ Implemented | `src/zee/responder/` — OS 別 full・egress 切断・**既定 dry_run** |
| 通知 | ✅ Implemented | `src/zee/notifier/` — ローカル必須・webhook 任意 |
| 復旧 | ✅ Implemented | `src/zee/recovery/` — `zee restore <asset_id>` 手動のみ |
| 計測 | ✅ Implemented | `src/zee/telemetry/` — JSON Lines・レイテンシ・誤検知マーカー |

導入手順とコマンドは → [README.md の MVP セクション](./README.md#mvp--動く囮トリップワイヤ)

---

<sub>各層の詳細・後続フェーズの追加は順次行います。</sub>
