"""Containment report export (`zee export`).

2026-10-01: 重要電子計算機に対する不正な行為による被害の防止に関する法律
(令和7年法律第42号, 通称 サイバー対処能力強化法) took effect. Zee does not
access or act on an attacker's machines — the statutory power to do that
(サイバー危害防止措置, 警察官職務執行法 第6条の2) belongs to police officers
(and, through 準用, to SDF officers), not to private parties or tools. This
module does the other half: turn what Zee already recorded (containment
events, hash-chained) into a file the operator can hand to whoever they
choose to report to. Zee does not decide whether a report is required or
where it goes; see the README `法制度との関係` section and
`docs/containment-report-mapping.md` (the field-by-field source of truth
this code implements — keep them in sync).
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .. import __version__
from ..errors import Z702_INVALID_TIME_RANGE, ZeeError
from ..mcp.reader import EventReader
from .events_log import TAMPER_STATUSES, default_log_dir, verify_chain

SCHEMA_VERSION = "1"

# Fields Zee has no way to know (identity, network-layer data it never
# observes, the operator's own account). Present-but-placeholder so the
# operator sees the field exists and fills it in — never guessed at.
_OPERATOR_FILLS_IN = "利用者が記入"
_ZEE_DOES_NOT_RECORD = "不明（Zeeはこの情報を記録しません）"

# 報告命令（令和8年内閣府・総務省ほか令第4号）第4条第3項 の報告事項 第1〜7号。
# Zee が出せるのは第3〜6号の「一部の材料」だけ。該当性の判断と記入は利用者。
_STATUTORY_ITEMS = [
    ("1 報告の区分", _OPERATOR_FILLS_IN),
    ("2 特別社会基盤事業者の概要", _OPERATOR_FILLS_IN),
    ("3 特定侵害事象等の概要",
     "材料のみZeeが提供（incident_summary_auto・detected_at_first/last）。"
     "特定侵害事象等に当たるかの判断と記述は利用者"),
    ("4 特定侵害事象等が発生した特定重要電子計算機",
     "材料のみZeeが提供（affected_asset_ids＝利用者が付けた識別子）。"
     "特定重要電子計算機に当たるかの判断は利用者"),
    ("5 特定侵害事象等に関する技術的な事項",
     "一部のみZeeが提供（events の操作種別・検知元・確度・時刻）。"
     "通信元IP・通信内容はZeeが記録しないため利用者"),
    ("6 特定侵害事象等への対応に関する事項",
     "一部のみZeeが提供（active_containments＝端末内の遮断記録）。"
     "それ以外の対応は利用者"),
    ("7 その他特記事項", _OPERATOR_FILLS_IN),
]


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _parse_bound(name: str, value: Optional[str]) -> Optional[datetime]:
    if value is None or value == "":
        return None
    try:
        dt = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        raise ZeeError(Z702_INVALID_TIME_RANGE, f"{name}={value!r} は ISO8601 として解釈できません")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)  # TZ省略 = UTC（日付のみ = その日 00:00 UTC）
    return dt.astimezone(timezone.utc)


def parse_period(since: Optional[str], until: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Strictly parse --since/--until; return them as UTC ISO8601 strings.

    Invalid values and since > until raise Z702 — never "no filter".
    Comparison is on real instants, so +09:00 and +00:00 order correctly.
    """
    s = _parse_bound("since", since)
    u = _parse_bound("until", until)
    if s and u and s > u:
        raise ZeeError(Z702_INVALID_TIME_RANGE, f"since={since} until={until}")
    return (s.isoformat() if s else None, u.isoformat() if u else None)


def _chain_summary(v: dict[str, Any]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for r in v["results"]:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    tamper = any(counts.get(s, 0) for s in TAMPER_STATUSES)
    if v["read_error"]:
        status = "unverifiable"
    elif tamper:
        status = "tamper_suspected"
    elif not v["results"]:
        status = "no_records"
    else:
        status = "ok"
    return {
        "status": status,
        "files": v["files"],
        "read_error": v["read_error"],
        "total_lines": len(v["results"]),
        "counts": counts,
        "tamper_suspected": tamper,
        "partial_last_line": counts.get("partial", 0) > 0,
        "problems": [r for r in v["results"] if r["status"] != "ok"][:50],
    }


def build_export(
    *,
    log_dir: Optional[Path] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    redact_paths: bool = True,
    limit: int = 0,
) -> dict[str, Any]:
    """Assemble the export document. Writes nothing (no mkdir/chmod either).

    `since`/`until` are validated with parse_period (Z702 on bad input).
    `limit` > 0 caps the `events` list (newest first); every count and
    summary is still computed over ALL events in the period, and the
    truncation is stated in `events_total` / `events_included`.
    """
    since_n, until_n = parse_period(since, until)
    ld = log_dir or default_log_dir()
    reader = EventReader(log_dir=ld, redact_paths=redact_paths)
    events = reader.query_events(since=since_n, until=until_n, limit=0)
    containments = reader.active_containments()

    events_chain = _chain_summary(verify_chain(ld / "events.jsonl"))
    metrics_chain = _chain_summary(verify_chain(ld / "metrics.jsonl"))

    change_n = sum(1 for e in events if e.get("op_class") == "change")
    read_n = sum(1 for e in events if e.get("op_class") == "read")
    first_seen = events[-1]["timestamp"] if events else None  # newest-first
    last_seen = events[0]["timestamp"] if events else None

    if events or containments:
        # Facts only. Whether a cut actually ran depends on response_mode
        # and dry_run, so the summary never says "Zee cut ...".
        incident_summary = (
            f"対象期間に {len(events)} 件のトラップイベントを記録"
            f"（変更系 {change_n} 件・読み取り系 {read_n} 件、"
            f"最初 {first_seen or '不明'}・最後 {last_seen or '不明'}）。"
            f"エクスポート時点で解除されていない遮断記録（cut_state.jsonl）: "
            f"{len(containments)} 件。遮断が実際に行われたかは active_containments "
            "と metrics.jsonl の記録で確認できます（dry_run 設定では遮断は行われません）。"
            "Zee は攻撃元の機器への接続・操作を行う機能を持ちません。"
        )
    else:
        incident_summary = "対象期間にトラップイベントの記録はありません。"

    shown = events[:limit] if limit and limit > 0 else events

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "zee_version": __version__,
        "period": {"since": since_n, "until": until_n, "timezone": "UTC"},
        "redacted": redact_paths,
        "chain_verification": {
            "events_jsonl": events_chain,
            "metrics_jsonl": metrics_chain,
            "note": (
                "Zee がこの端末上の events.jsonl / metrics.jsonl（ローテーション済みを含む）の"
                "ハッシュチェーンを検証した結果です。検知できるのは、途中の行の書き換え・"
                "削除・並べ替え、先頭の欠落、ハッシュ付き行の後に置かれたハッシュなし行です。"
                "検知できないもの：末尾の行の削除（切り詰め）、およびログを書き換えられる"
                "攻撃者による全ハッシュの再計算（ハッシュは鍵なしのため）。"
                "export_sha256 が示すのは、このエクスポートが出力された時点以降に"
                "変更されていないこと（別の場所に控えた値と一致する場合）だけで、"
                "出力前のログが正しかったことは示しません。"
            ),
        },
        "events_total": len(events),
        "events_included": len(shown),
        "events_truncated": len(shown) < len(events),
        "events": shown,
        "active_containments": containments,
        "statutory_report_items": {
            "note": (
                "重要電子計算機に対する不正な行為による被害の防止に関する法律 第5条、"
                "同法に基づく報告命令（令和8年内閣府・総務省ほか令第4号）第4条第3項の"
                "報告事項との対応です。報告義務を負うのは同法第2条第3項の特別社会基盤事業者で、"
                "報告書の様式は所管大臣及び内閣総理大臣が定めます（Zee は様式を未確認）。"
                "該当性の判断・記入は利用者が行います。"
            ),
            **{k: v for k, v in _STATUTORY_ITEMS},
        },
        "report_fields": {
            "note": (
                "任意の相談・報告（JPCERT/CC インシデント報告様式など）で一般に"
                "求められる項目への対応です（docs/containment-report-mapping.md 参照）。"
            ),
            "reporter_name": _OPERATOR_FILLS_IN,
            "reporter_organization": _OPERATOR_FILLS_IN,
            "reporter_department": _OPERATOR_FILLS_IN,
            "reporter_phone": _OPERATOR_FILLS_IN,
            "reporter_email": _OPERATOR_FILLS_IN,
            "report_purpose": _OPERATOR_FILLS_IN,
            "incident_summary_auto": incident_summary,
            "incident_summary_operator": _OPERATOR_FILLS_IN,
            "source_ip_or_hostname": _ZEE_DOES_NOT_RECORD,
            "affected_asset_ids": sorted({e["asset_id"] for e in events}),
            "protocol_or_port": _ZEE_DOES_NOT_RECORD,
            "related_software_hardware": _OPERATOR_FILLS_IN,
            "detected_at_first": first_seen,
            "detected_at_last": last_seen,
            "timezone": "UTC（Zee が記録する detected_at は UTC の ISO8601）",
            "log_evidence": (
                "同エクスポート内 events フィールド。各行のハッシュは含めていません"
                "（元ログのハッシュチェーンは Zee 側で検証済み — chain_verification 参照）。"
            ),
        },
    }


def attach_digest(export: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """Compute export_sha256 over `export` as-is and return (export+digest, digest).

    Embedding the digest is a convenience for matching a printed value;
    it only means something if the operator keeps a copy elsewhere.
    """
    digest = hashlib.sha256(_canonical(export).encode("utf-8")).hexdigest()
    out = dict(export)
    out["export_sha256"] = digest
    return out, digest


_STATUS_JA = {
    "ok": "異常は検出されませんでした",
    "no_records": "記録なし",
    "tamper_suspected": "★改ざん・欠落の疑いあり",
    "unverifiable": "★検証不能（読み取りに失敗）",
}


def render_text(export: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# Zee 封じ込め証跡エクスポート")
    lines.append(f"生成日時: {export['generated_at']} (zee {export['zee_version']})")
    p = export["period"]
    lines.append(f"対象期間（UTC）: {p['since'] or '(指定なし)'} 〜 {p['until'] or '(指定なし)'}")
    lines.append(f"マスク（detail）: {'有効' if export['redacted'] else '無効（--no-redact）'}")
    lines.append("")
    cv = export["chain_verification"]
    for name, key in (("events.jsonl", "events_jsonl"), ("metrics.jsonl", "metrics_jsonl")):
        c = cv[key]
        counts = " ".join(f"{k}={v}" for k, v in sorted(c["counts"].items())) or "-"
        lines.append(f"証跡の検証 [{name}]: {_STATUS_JA[c['status']]}  ({counts})")
        if c["read_error"]:
            lines.append(f"  読み取り失敗: {c['read_error']}")
        if c["partial_last_line"]:
            lines.append("  最終行が書き込み途中の可能性があります（改ざん判定には含めていません）")
        if c["counts"].get("legacy"):
            lines.append("  legacy = ハッシュ導入前の行（未検証）")
    lines.append(cv["note"])
    lines.append("")
    lines.append(export["report_fields"]["incident_summary_auto"])
    lines.append("")
    lines.append(
        f"検知イベント件数: {export['events_total']}"
        + (f"（このファイルには新しい順に {export['events_included']} 件のみ収録）"
           if export["events_truncated"] else "")
    )
    lines.append(f"解除されていない遮断記録: {len(export['active_containments'])} 件")
    lines.append("")
    lines.append("## 法定報告事項との対応（報告命令 第4条第3項）")
    for k, v in export["statutory_report_items"].items():
        if k != "note":
            lines.append(f"- {k}: {v}")
    lines.append(export["statutory_report_items"]["note"])
    lines.append("")
    lines.append("## 任意報告の項目対応（詳細は docs/containment-report-mapping.md）")
    for k, v in export["report_fields"].items():
        if k in ("note", "incident_summary_auto"):
            continue
        lines.append(f"- {k}: {v}")
    lines.append("")
    lines.append(
        "Zee は攻撃元の機器への接続・操作（いわゆる無害化）を行いません。法律上その権限は"
        "警察官・自衛官に与えられており、Zee にはありません。この記録を提出するか、"
        "どこに提出するかは利用者ご自身で判断してください。Zee は法令適合を保証しません。"
    )
    if "export_sha256" in export:
        lines.append("")
        lines.append(f"export_sha256: {export['export_sha256']}")
        lines.append(
            "↑この値を、このファイルとは別の場所（提出メール本文など）に控えてください。"
            "示せるのは出力時点以降に変更されていないことだけです。"
        )
    return "\n".join(lines)
