# 安野貴博氏「政府への7つの提言私案」と Zee の実装の対応表

対象：安野貴博「AI時代のサイバー攻撃、度重なる情報漏洩からの守りを固めるための政府への7つの提言私案」（note、2026-10-12 公開）
https://note.com/takahiroanno/n/n27e77cc9bb80

作成：2026-10-13。Zee 側の記述は、この日の `origin/main`（公開版・HEAD `abd956f`）と手元の `main`（未公開のコミット11件を含む）の実物から取った。提言の項目名は記事の見出しをそのまま使い、内容は要約にとどめた。

実装状況は3つに分けた。
- **検証済み**：実装に加えて、テストファイルと実行記録（WORKLOG の passed 件数や実機での実行）がある
- **実装済み**：コードはあるが、実機での検証記録が無い（または一部の環境だけ）
- **未実装**：設計のみ、または機能が無い

「公開」は `origin/main` に入っていること、「手元のみ」は手元の `main` にだけあり未公開であることを示す。

| 提言 | Zee の該当機能 | 実装状況 | 根拠 |
|---|---|---|---|
| 1. AIにはAIを：人間が守るという前提を捨て、AIで継続的に守りを固める | 入口ゲート `zee gate add`（AIスキル・MCP・npm・PyPI・VS Code 拡張を導入前に実行せず静的検査）／`zee gate audit`（配布後のすり替え監視） | 検証済み（公開・v0.7.0〜） | `src/zee/gate/`、`docs/gate.md`、`tests/test_gate*.py`、導入 `e0da543`、G501 強化 v0.12.0（CHANGELOG・WORKLOG「427 passed」）。HDR の第三者skill審査で実機実行2件（2026-09-02 mono-color-skill、2026-10-06 Angelic-Angel。ai-virtual-corp `.claude/decisions.md`） |
| 2. 被害を受けた個人に対してプッシュ型で支援を行う：信用情報機関への報告、集団訴訟、損害賠償請求までの自動化を目指す | 対応なし（Zee は事業者・個人の端末側の道具で、被害者個人への通知・支援の機能は無い） | — | — |
| 3. まじめな企業が馬鹿を見ない健全なインセンティブ設計をする | 脆弱性の受付方針とセーフハーバーの公開（SECURITY.md・日本語版 SECURITY.ja.md。受領7日・初期判定14日・協調公開の目標90日）。GitHub の非公開報告窓口を有効化 | 実装済み（公開） | `SECURITY.md`、`SECURITY.ja.md`（`4a9f31b`・`94961ea`）。インセンティブ設計そのものは政策の領域で、Zee は判定項目の実例を示す位置づけ |
| 4. 企業に対する注意喚起とパトロールの強化 | 囮トリップワイヤと自動封じ込め（囮への書き込み・削除・改名を検知し、`response_mode: auto` かつ `dry_run: false` の資産を遮断。既定は dry_run）。無料・MIT | macOS：検証済み／Linux・Windows：実装済み（公開） | `src/zee/`（watcher・responder・recovery）、README「Mac で動作検証済み。Linux はコード上完成、実機での連続稼働検証は未実施。Windows は実機検証は未実施」 |
| 5. 事業者が持たなければならないデータをなるべく最小化する | 対応なし | — | — |
| 6. 人材・技術・窓口・統計などセキュリティを支えるリソースにより投資する（攻撃の実態把握） | ハッシュチェーン付きの記録（`events.jsonl`・`metrics.jsonl`）と `zee export`（報告用ファイルへの書き出し・送信しない）。報告命令 第4条第3項の報告事項との対応付け | 検証済み（公開・v0.11.0〜） | `src/zee/telemetry/report_export.py`、`tests/test_export_cli.py`、`tests/test_events_log_chain.py`、`docs/containment-report-mapping.md`、`8108adc` |
| 6.（同上） | `zee incident-report`（export を警察／個人情報保護委員会への相談用文書 json/txt/html にまとめる・送信しない） | 検証済み（公開・v0.12.0〜） | `src/zee/report/incident_report.py`、`tests/test_incident_report.py`、`docs/design/incident-report.md`、`98c40c9`〜`f532892`（WORKLOG「332 passed」） |
| 7. 情報漏洩以上の危機事態に備え、ライフラインの守りを固める（サイバー版事故調査委員会） | 6 と同じ証跡（チェーン検証結果 `chain_verification` と出力ファイルのハッシュ値 `export_sha256` を同梱）。攻撃元への措置は行わず、国の措置につなぐ材料づくりに役割を限る | 検証済み（公開） | README「法制度との関係（2026-10-01〜）」、`docs/containment-report-mapping.md` §3 |
| 1・4（参考） | 送信の保留と別端末の署名による解除（`zee.egress`、CLI・監視には未接続） | 実装済み（手元のみ・未公開） | `docs/design/egress-approval.md`、`c09d78a` |
| 4・6（参考） | 問い合わせで発火する canary（受信側は `examples/` のみ） | 実装済み（手元のみ・未公開） | `docs/design/query-canary.md`、`e207e57` |
| 4（参考） | 自動封じ込めの ON/OFF 状態の記録（`zee.responder.permission`、未接続） | 実装済み（手元のみ・未公開） | `97be50e` |
| 4（参考） | 封じ込めの明示的な ON/OFF 切り替え | 未実装 | CHANGELOG [Unreleased]「the explicit ON/OFF switch itself is still to come」 |

## Zee の立ち位置（対応表を読む前提）

Zee は、侵入された後の端末で、盗まれる前に気づいて止める（封じ込める）ことで時間と記録を稼ぎ、警察・所管官庁などの措置につなぐ側の道具です。攻撃元の機器への措置（いわゆる無害化）は行いません。法律上その権限もありません（README「法制度との関係」）。
