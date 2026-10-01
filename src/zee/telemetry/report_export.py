"""Containment report export (`zee export`).

2026-10-01: the サイバー対処能力強化法 (重要電子計算機に対する不正な行為
による被害の防止に関する法律) took effect. Neutralising an attacker's
infrastructure is now limited by law to the police and the Self-Defense
Forces — Zee does not do that and never has. This module does the other
half: turn what Zee already recorded (containment events, hash-chained
for tamper evidence) into a file the operator can hand to whoever they
choose to report to — a法定 report if they are a designated 特定社会
基盤事業者, or a voluntary one (police cyber-crime consultation desk,
JPCERT/CC) otherwise. Zee does not decide which; see the `法制度との
関係` README section and `docs/containment-report-mapping.md`.

What this module fills in automatically vs. what it leaves for the
operator to fill in by hand is spelled out field-by-field in
`docs/containment-report-mapping.md` — that mapping is the source of
truth this code implements; keep them in sync.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .. import __version__
from ..mcp.reader import EventReader
from .events_log import default_log_dir, verify_chain

SCHEMA_VERSION = "1"

# Fields a法定/任意 incident report commonly asks for that Zee has no
# way to know (identity, network-layer data it never observes, the
# operator's own free-text account). Left present-but-null in the
# export so the operator sees the field exists and fills it in — never
# guessed at.
_OPERATOR_FILLS_IN = "利用者が記入"
_ZEE_DOES_NOT_RECORD = "不明（Zeeはこの情報を記録しません）"


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _chain_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {"ok": 0, "legacy": 0, "corrupted": 0, "chain_break": 0}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    return {
        "total_lines": len(results),
        "counts": counts,
        "tamper_suspected": counts["corrupted"] > 0 or counts["chain_break"] > 0,
    }


def build_export(
    *,
    log_dir: Optional[Path] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    redact_paths: bool = True,
) -> dict[str, Any]:
    """Assemble the export document. Pure function — writes nothing.

    Ordering note: this must be called, and its result hashed, BEFORE
    `export_sha256` is computed and attached by the caller — the digest
    covers everything returned here, nothing more.
    """
    ld = log_dir or default_log_dir()
    reader = EventReader(log_dir=ld, redact_paths=redact_paths)
    events = reader.query_events(since=since, until=until, limit=0)
    containments = reader.active_containments()

    events_chain = verify_chain(ld / "events.jsonl")
    metrics_chain = verify_chain(ld / "metrics.jsonl")

    change_events = [e for e in events if e.get("op_class") == "change"]
    read_events = [e for e in events if e.get("op_class") == "read"]
    first_seen = events[-1]["timestamp"] if events else None  # query_events is newest-first
    last_seen = events[0]["timestamp"] if events else None

    incident_summary = (
        f"{len(events)} 件のトラップイベント（変更系 {len(change_events)} 件・"
        f"読み取り系 {len(read_events)} 件）を{first_seen or '不明'}〜"
        f"{last_seen or '不明'}の期間に検知。"
        f"現在アクティブな封じ込め: {len(containments)} 件。"
        "Zeeは端末内の書き込み・削除・リネームの自動遮断のみを行い、"
        "攻撃元への接続・無害化は行っていません。"
    ) if events or containments else "対象期間にトラップイベントの記録はありません。"

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "zee_version": __version__,
        "period": {"since": since, "until": until},
        "redacted": redact_paths,
        "chain_verification": {
            "events_jsonl": _chain_summary(events_chain),
            "metrics_jsonl": _chain_summary(metrics_chain),
            "note": (
                "この検証は個々の行の書き換え・削除を検出します。ファイル全体の"
                "差し替えは検出できません — export_sha256 を、このファイルとは"
                "別の場所（提出メール本文など）に控えてください。"
            ),
        },
        "events": events,
        "active_containments": containments,
        "report_fields": {
            "note": (
                "以下は主にJPCERT/CCインシデント報告様式の項目に対応させたものです"
                "（docs/containment-report-mapping.md参照）。特定社会基盤事業者の"
                "法定報告様式は本稿執筆時点で主務省令未公布のため対応未定です。"
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
            "timezone": "UTC（events.jsonlのdetected_atはすべてUTC ISO8601）",
            "log_evidence": "同エクスポート内 events フィールド（ハッシュチェーン付き）",
        },
    }


def attach_digest(export: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """Compute export_sha256 over `export` as-is and return (export+digest, digest).

    The digest is also embedded in the returned document for convenience
    when matching a printed value against the file, but embedding it
    does not make it tamper-evident on its own — see chain_verification
    note and the README's 法制度との関係 section.
    """
    import hashlib

    digest = hashlib.sha256(_canonical(export).encode("utf-8")).hexdigest()
    out = dict(export)
    out["export_sha256"] = digest
    return out, digest


def render_text(export: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# Zee 封じ込め証跡エクスポート")
    lines.append(f"生成日時: {export['generated_at']} (zee {export['zee_version']})")
    lines.append(f"対象期間: {export['period']['since'] or '(指定なし)'} 〜 {export['period']['until'] or '(指定なし)'}")
    lines.append(f"マスク（--redact）: {'有効' if export['redacted'] else '無効'}")
    lines.append("")
    cv = export["chain_verification"]
    for name, key in (("events.jsonl", "events_jsonl"), ("metrics.jsonl", "metrics_jsonl")):
        c = cv[key]["counts"]
        flag = "★改ざんの疑いあり" if cv[key]["tamper_suspected"] else "異常なし"
        lines.append(
            f"証跡整合性 [{name}]: {flag}  "
            f"(ok={c['ok']} legacy={c['legacy']} corrupted={c['corrupted']} chain_break={c['chain_break']})"
        )
    lines.append(cv["note"])
    lines.append("")
    lines.append(export["report_fields"]["incident_summary_auto"])
    lines.append("")
    lines.append(f"検知イベント件数: {len(export['events'])}")
    lines.append(f"現在アクティブな封じ込め: {len(export['active_containments'])} 件")
    lines.append("")
    lines.append("## 報告項目対応表（詳細は docs/containment-report-mapping.md）")
    for k, v in export["report_fields"].items():
        if k in ("note", "incident_summary_auto"):
            continue
        lines.append(f"- {k}: {v}")
    lines.append("")
    lines.append(
        "Zeeは攻撃元へのアクセス・無害化を行いません（実施権限は警察・自衛隊に法律上限定"
        "されています）。この記録の提出要否・提出先は利用者ご自身でご確認ください。"
        "Zeeは法令適合を保証しません。"
    )
    if "export_sha256" in export:
        lines.append("")
        lines.append(f"export_sha256: {export['export_sha256']}")
        lines.append(
            "↑この値を、このファイルとは別の場所（提出メール本文など）に控えてください。"
        )
    return "\n".join(lines)
