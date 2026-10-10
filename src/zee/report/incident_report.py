"""Bundle Zee's own records into a document a human can hand to police or
to the Personal Information Protection Commission (PPC).

This module never submits, uploads, or sends anything — it has no
import of ``urllib``, ``http.client``, ``socket``, ``smtplib``,
``requests``, or ``zee.notifier`` (enforced by
tests/test_incident_report.py::test_no_network_imports). Its only input
is a JSON file ``zee export`` already wrote (docs/design/incident-report.md
§1). That file is treated as untrusted: its shape and types are checked,
only known event fields are carried over, and control characters in its
strings are made visible before they reach the text/html report.

Bundling an "incident" is the operator's call, not an automatic one:
Zee does not record a connection source for file events
(see docs/containment-report-mapping.md §5), so there is nothing here
to cluster on beyond what the operator already scoped with
`zee export --since/--until` (§2 of the design doc).
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from ..errors import Z1001_UNKNOWN_RECIPIENT, Z1004_EXPORT_FILE_REQUIRED, ZeeError
from .recipients import BY_NAME, POLICE_PHONE_CONSULT, Recipient

SCHEMA_VERSION = "1"

_OPERATOR_FILLS_IN = "利用者が記入"
_ZEE_DOES_NOT_RECORD = "不明（Zeeはこの情報を記録しません）"
_HEURISTIC_NOTE = (
    "この事案の範囲（期間）は利用者が zee export で指定したものです。"
    "Zee が接続元から自動的に同一主体と判定したものではありません"
    "（Zeeは接続元IPを記録しないため、自動判定の根拠自体を持ちません）。"
)
_UNREDACTED_NOTE = (
    "注意: 元の zee export は --no-redact で作られており、パス等が伏せられずに含まれています。"
    "提出前に内容を確認してください。"
)

_STATUTORY_PPC_ITEMS_ORDER = (
    "1 概要",
    "2 漏えい等が発生し、又は発生したおそれがある個人データの項目",
    "3 漏えい等が発生し、又は発生したおそれがある個人データに係る本人の数",
    "4 原因",
    "5 二次被害又はそのおそれの有無及びその内容",
    "6 本人への対応の実施状況",
    "7 公表の実施状況",
    "8 再発防止のための措置",
    "9 その他参考となる事項",
)

_SUPPORTED_EXPORT_SCHEMA_VERSIONS = {"1"}
# Only these fields of each record are carried into the report; anything
# else an export (or a hand-edited file) carries is dropped.
_EVENT_FIELDS = ("schema_version", "event_id", "timestamp", "source", "confidence",
                 "op_class", "asset_id", "decoy_ref", "detail")
_CONTAINMENT_FIELDS = ("asset_id", "method", "cut_at", "platform", "modified")


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_str_list(v: Any) -> bool:
    return isinstance(v, list) and all(isinstance(x, str) for x in v)


def _is_opt_str(v: Any) -> bool:
    return v is None or isinstance(v, str)


def _check(cond: bool, path: Path, what: str) -> None:
    if not cond:
        raise ZeeError(Z1004_EXPORT_FILE_REQUIRED, f"{path}: {what}")


def _pick(rec: Any, fields: tuple[str, ...], path: Path, what: str) -> dict[str, Any]:
    _check(isinstance(rec, dict), path, f"{what} の要素がオブジェクトではありません")
    out = {k: rec[k] for k in fields if k in rec}
    for k, v in out.items():
        ok = _is_str_list(v) if k == "modified" else _is_opt_str(v)
        _check(ok, path, f"{what}.{k} の型が不正です")
    return out


def load_export(path: Path) -> dict[str, Any]:
    """Read a `zee export --out <prefix>` JSON file and validate its shape.

    Missing or mistyped fields raise Z1004 — they are never filled with
    defaults (a missing count must not read as "0 events"). Returns only
    the fields this module uses, with events / containments reduced to
    their known fields.
    """
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ZeeError(Z1004_EXPORT_FILE_REQUIRED, f"{path}: {e}") from e
    _check(isinstance(data, dict), path, "JSONオブジェクトではありません")
    _check(isinstance(data.get("schema_version"), str)
           and data["schema_version"] in _SUPPORTED_EXPORT_SCHEMA_VERSIONS,
           path, "schema_version が対応する文字列ではありません")
    rf = data.get("report_fields")
    _check(isinstance(rf, dict), path, "report_fields がオブジェクトではありません")
    _check(isinstance(rf.get("incident_summary_auto"), str), path,
           "report_fields.incident_summary_auto が文字列ではありません")
    for k in ("detected_at_first", "detected_at_last"):
        _check(k in rf and _is_opt_str(rf[k]), path, f"report_fields.{k} が文字列または null ではありません")
    _check(_is_str_list(rf.get("affected_asset_ids")), path,
           "report_fields.affected_asset_ids が文字列のリストではありません")
    for k in ("events_total", "events_included"):
        _check(_is_int(data.get(k)) and data[k] >= 0, path, f"{k} が0以上の整数ではありません")
    for k in ("events_truncated", "redacted"):
        _check(isinstance(data.get(k), bool), path, f"{k} が真偽値ではありません")
    for k in ("events", "active_containments"):
        _check(isinstance(data.get(k), list), path, f"{k} がリストではありません")
    cv = data.get("chain_verification")
    _check(isinstance(cv, dict), path, "chain_verification がオブジェクトではありません")
    chain: dict[str, Any] = {}
    for k in ("events_jsonl", "metrics_jsonl"):
        c = cv.get(k)
        _check(isinstance(c, dict) and isinstance(c.get("status"), str), path,
               f"chain_verification.{k}.status が文字列ではありません")
        chain[k] = {"status": c["status"]}

    return {
        "schema_version": data["schema_version"],
        "redacted": data["redacted"],
        "report_fields": {k: rf[k] for k in ("incident_summary_auto", "detected_at_first",
                                             "detected_at_last", "affected_asset_ids")},
        "events_total": data["events_total"],
        "events_included": data["events_included"],
        "events_truncated": data["events_truncated"],
        "events": [_pick(e, _EVENT_FIELDS, path, "events") for e in data["events"]],
        "active_containments": [_pick(c, _CONTAINMENT_FIELDS, path, "active_containments")
                                for c in data["active_containments"]],
        "chain_verification": chain,
    }


def build_incident_report(
    *,
    export: dict[str, Any],
    recipient: str,
    incident_label: Optional[str] = None,
) -> dict[str, Any]:
    """Assemble the document from a `load_export` result. Writes nothing."""
    if recipient not in BY_NAME:
        raise ZeeError(Z1001_UNKNOWN_RECIPIENT, repr(recipient))
    rf = export["report_fields"]

    doc: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "recipient": recipient,
        "incident_label": incident_label or _OPERATOR_FILLS_IN,
        "bundling_note": _HEURISTIC_NOTE,
        "containment_export": {
            "redacted": export["redacted"],
            "incident_summary_auto": rf["incident_summary_auto"],
            "detected_at_first": rf["detected_at_first"],
            "detected_at_last": rf["detected_at_last"],
            "affected_asset_ids": rf["affected_asset_ids"],
            "events_total": export["events_total"],
            "events_included": export["events_included"],
            "events_truncated": export["events_truncated"],
            "events": export["events"],
            "active_containments": export["active_containments"],
            "chain_verification": export["chain_verification"],
        },
        "submission": {
            "note": (
                "この文書は提出用の材料です。Zee はここからの送信・提出を行いません。"
                "提出は利用者ご自身で行ってください。"
            ),
        },
    }

    if recipient == "police":
        doc["police_fields"] = {
            "reporter_name": _OPERATOR_FILLS_IN,
            "reporter_organization": _OPERATOR_FILLS_IN,
            "reporter_phone": _OPERATOR_FILLS_IN,
            "reporter_email": _OPERATOR_FILLS_IN,
            "report_purpose": _OPERATOR_FILLS_IN,
            "incident_summary_operator": _OPERATOR_FILLS_IN,
            "source_ip_or_hostname": _ZEE_DOES_NOT_RECORD,
            "note": "警察庁オンライン受付窓口の固定入力項目は未確認のため、既存の report_fields 形式のまま提示します。",
        }
    else:
        doc["ppc_statutory_items"] = {
            "1 概要": rf["incident_summary_auto"] or _OPERATOR_FILLS_IN,
            "2 漏えい等が発生し、又は発生したおそれがある個人データの項目": _ZEE_DOES_NOT_RECORD,
            "3 漏えい等が発生し、又は発生したおそれがある個人データに係る本人の数": _OPERATOR_FILLS_IN,
            "4 原因": (
                "囮の検知イベントの記録あり（不正アクセス等の材料。該当性の判断は利用者）"
                if export["events_total"] else _OPERATOR_FILLS_IN
            ),
            "5 二次被害又はそのおそれの有無及びその内容": _OPERATOR_FILLS_IN,
            "6 本人への対応の実施状況": _OPERATOR_FILLS_IN,
            "7 公表の実施状況": _OPERATOR_FILLS_IN,
            "8 再発防止のための措置": _OPERATOR_FILLS_IN,
            "9 その他参考となる事項": _OPERATOR_FILLS_IN,
            "note": (
                "個人情報保護法26条・施行規則第8条（e-Gov法令API v2で確認済み）の9項目。"
                "速報は速やかに（条文上の日数指定なし）。確報は知った日から30日以内、"
                "不正アクセス等（施行規則第7条第3号類型）の場合は60日以内。"
                "どちらが適用されるかは利用者が判断します。"
            ),
        }
    return doc


_CTRL = re.compile("[\x00-\x1f\x7f-\x9f  ]")
_CTRL_NAMES = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _vis(s: Any) -> str:
    """Make control characters (C0/C1, incl. newlines) visible as escapes,
    so a string from the export cannot start a fake line or heading."""
    return _CTRL.sub(lambda m: _CTRL_NAMES.get(m.group(), f"\\u{ord(m.group()):04x}"), str(s))


def _recipient_block(r: Recipient, *, heading: str = "提出先") -> list[str]:
    lines = [f"## {heading}: {r.agency}", f"参照URL: {r.url}（確認日 {r.as_of}。変わりうるため提出前に再確認してください）"]
    if r.phone:
        lines.append(f"電話: {r.phone}")
    if r.hours and "未確認" not in r.hours:
        lines.append(f"受付時間: {r.hours}")
    if r.note:
        lines.append(r.note)
    return lines


def render_text(doc: dict[str, Any]) -> str:
    # Every value that can come from the export or the CLI goes through _vis.
    ce = doc["containment_export"]
    lines: list[str] = ["# Zee 当局向け報告書（事案まとめ）", f"生成日時: {doc['generated_at']}",
                        f"事案ラベル: {_vis(doc['incident_label'])}", "", doc["bundling_note"]]
    if not ce["redacted"]:
        lines.append(_UNREDACTED_NOTE)
    lines.append("")

    lines.append("## 封じ込め証跡（zee export 由来）")
    lines.append(_vis(ce["incident_summary_auto"]) or "（記録なし）")
    lines.append(f"検知期間: {_vis(ce['detected_at_first'] or '不明')} 〜 {_vis(ce['detected_at_last'] or '不明')}")
    lines.append(f"対象資産: {', '.join(_vis(a) for a in ce['affected_asset_ids']) or '（なし）'}")
    lines.append(
        f"検知イベント件数: {ce['events_total']}"
        f"（この文書のJSONに{ce['events_included']}件を収録"
        + ("・新しい順に一部のみ" if ce["events_truncated"] else "")
        + "。個別イベントの時刻・操作種別・検知元は <out>.json の containment_export.events を参照）"
    )
    lines.append(f"解除されていない遮断記録: {len(ce['active_containments'])} 件")
    for name, key in (("events.jsonl", "events_jsonl"), ("metrics.jsonl", "metrics_jsonl")):
        lines.append(f"証跡の改ざん検知 [{name}]: {_vis(ce['chain_verification'][key]['status'])}")
    lines.append("")

    if doc["recipient"] == "police":
        lines.append("## 報告項目（警察向け・任意通報）")
        for k, v in doc["police_fields"].items():
            if k != "note":
                lines.append(f"- {k}: {v}")
        lines.append(doc["police_fields"]["note"])
    else:
        lines.append("## 法定報告事項（個人情報保護委員会向け・施行規則第8条）")
        for k in _STATUTORY_PPC_ITEMS_ORDER:
            lines.append(f"- {k}: {_vis(doc['ppc_statutory_items'][k])}")
        lines.append(doc["ppc_statutory_items"]["note"])
    lines.append("")

    # The body above carries only the chosen recipient's items; the footer
    # always lists both contact points and states that the police report
    # (voluntary) and the PPC report (APPI Art. 26 duty) are separate
    # procedures with separate deadlines, so the two are not confused.
    lines.append("## 参照窓口（警察とPPCは別の手続き・別の期限です）")
    lines.extend(_recipient_block(BY_NAME["police"], heading="参照窓口（警察・任意通報）"))
    lines.append("")
    lines.extend(_recipient_block(POLICE_PHONE_CONSULT, heading="参照窓口（警察・電話相談）"))
    lines.append("")
    lines.extend(_recipient_block(BY_NAME["ppc"], heading="参照窓口（PPC・個人情報保護法26条の報告義務）"))

    lines.append("")
    lines.append(doc["submission"]["note"])
    return "\n".join(lines)


def _esc(s: Any) -> str:
    """Text-node escaping only — does not escape quotes, so not safe for
    embedding into an HTML attribute value (only used inside <body> text here)."""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def render_html(doc: dict[str, Any]) -> str:
    """Zero-dependency HTML — print-to-PDF from any browser (no PDF library added, see design doc §4.4)."""
    body = render_text(doc)
    esc = _esc(body)
    return (
        "<!doctype html><html lang=\"ja\"><head><meta charset=\"utf-8\">"
        "<title>Zee 当局向け報告書</title>"
        "<style>body{font-family:sans-serif;white-space:pre-wrap;"
        "max-width:40em;margin:2em auto;line-height:1.6}</style></head>"
        f"<body>{esc}</body></html>"
    )
