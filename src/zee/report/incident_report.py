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
from ..telemetry.events_log import TAMPER_STATUSES
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


def _is_str(v: Any) -> bool:
    return isinstance(v, str)


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_str_list(v: Any) -> bool:
    return isinstance(v, list) and all(isinstance(x, str) for x in v)


def _is_opt_str(v: Any) -> bool:
    return v is None or isinstance(v, str)


def _is_count_map(v: Any) -> bool:
    return isinstance(v, dict) and all(isinstance(k, str) and _is_int(n) and n >= 0 for k, n in v.items())


def _is_bool(v: Any) -> bool:
    return isinstance(v, bool)


# Record contracts, matching what `zee export` writes: every key is
# required (missing -> Z1004), each value must pass its check, and keys
# not listed here are dropped (never copied into the report).
# events: zee.mcp.reader.EventReader._canonical
_EVENT_SCHEMA = {
    "schema_version": _is_str, "event_id": _is_str, "timestamp": _is_str,
    "source": _is_opt_str, "confidence": _is_opt_str, "op_class": _is_opt_str,
    "asset_id": _is_str, "decoy_ref": _is_opt_str, "detail": _is_str,
}
# active_containments: zee.mcp.reader.EventReader.active_containments
_CONTAINMENT_SCHEMA = {
    "asset_id": _is_str, "method": _is_str, "cut_at": _is_str,
    "platform": _is_str, "modified": _is_str_list,
}
# chain_verification.<log>: zee.telemetry.report_export._chain_summary
_CHAIN_SCHEMA = {
    "status": _is_str, "files": _is_str_list, "read_error": _is_opt_str,
    "total_lines": lambda v: _is_int(v) and v >= 0, "counts": _is_count_map,
    "tamper_suspected": _is_bool, "partial_last_line": _is_bool,
    "problems": lambda v: isinstance(v, list),
}
_PROBLEM_SCHEMA = {"file": _is_str, "line": _is_int, "status": _is_str}
# Per-line statuses verify_chain() can emit, and _chain_summary()'s cap on `problems`.
_LINE_STATUSES = frozenset({"ok", "legacy", "partial"}) | TAMPER_STATUSES
_PROBLEMS_CAP = 50


def _check(cond: bool, path: Path, what: str) -> None:
    if not cond:
        raise ZeeError(Z1004_EXPORT_FILE_REQUIRED, f"{path}: {what}")


def _pick(rec: Any, schema: dict[str, Any], path: Path, what: str) -> dict[str, Any]:
    _check(isinstance(rec, dict), path, f"{what} がオブジェクトではありません")
    for k, ok in schema.items():
        _check(k in rec, path, f"{what}.{k} がありません")
        _check(ok(rec[k]), path, f"{what}.{k} の型が不正です")
    return {k: rec[k] for k in schema}


def _check_chain_consistent(c: dict[str, Any], path: Path, what: str) -> None:
    """Cross-check one chain summary against the rules _chain_summary()
    derives it by, so editing one field (e.g. emptying `counts`) cannot
    hide unverified or anomalous lines while the rest still looks valid."""
    counts = c["counts"]
    _check(set(counts) <= _LINE_STATUSES and all(n >= 1 for n in counts.values()), path,
           f"{what}.counts に未知の種別または0以下の値があります")
    _check(sum(counts.values()) == c["total_lines"], path, f"{what}.counts の合計が total_lines と一致しません")
    tamper = any(counts.get(s, 0) for s in TAMPER_STATUSES)
    _check(c["tamper_suspected"] == tamper, path, f"{what}.tamper_suspected が counts と矛盾しています")
    _check(c["partial_last_line"] == ("partial" in counts), path, f"{what}.partial_last_line が counts と矛盾しています")
    expected = ("unverifiable" if c["read_error"] else "tamper_suspected" if tamper
                else "no_records" if not c["total_lines"] else "ok")
    _check(c["status"] == expected, path, f"{what}.status={c['status']!r} が counts から導かれる {expected!r} と一致しません")
    # problems = the first _PROBLEMS_CAP non-ok lines, so its length is exact
    # and each status in it can appear at most counts[status] times.
    non_ok = c["total_lines"] - counts.get("ok", 0)
    _check(len(c["problems"]) == min(non_ok, _PROBLEMS_CAP), path, f"{what}.problems の件数が counts と一致しません")
    seen: dict[str, int] = {}
    for pr in c["problems"]:
        seen[pr["status"]] = seen.get(pr["status"], 0) + 1
    _check(all(st != "ok" and n <= counts.get(st, 0) for st, n in seen.items()), path,
           f"{what}.problems の種別が counts の内訳と一致しません")


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
    total, included, events = data["events_total"], data["events_included"], data["events"]
    _check(included == len(events), path, f"events_included={included} が events の件数 {len(events)} と一致しません")
    _check(total >= included, path, f"events_total={total} が events_included={included} より小さい値です")
    _check(data["events_truncated"] == (included < total), path,
           "events_truncated が events_total / events_included と矛盾しています")
    cv = data.get("chain_verification")
    _check(isinstance(cv, dict), path, "chain_verification がオブジェクトではありません")
    _check(isinstance(cv.get("note"), str), path, "chain_verification.note が文字列ではありません")
    chain: dict[str, Any] = {"note": cv["note"]}
    for k in ("events_jsonl", "metrics_jsonl"):
        c = _pick(cv.get(k), _CHAIN_SCHEMA, path, f"chain_verification.{k}")
        problems = []
        for i, pr in enumerate(c["problems"]):
            q = _pick(pr, _PROBLEM_SCHEMA, path, f"chain_verification.{k}.problems[{i}]")
            if "reason" in pr:
                _check(_is_str(pr["reason"]), path, f"chain_verification.{k}.problems[{i}].reason の型が不正です")
                q["reason"] = pr["reason"]
            problems.append(q)
        c["problems"] = problems
        _check_chain_consistent(c, path, f"chain_verification.{k}")
        chain[k] = c

    return {
        "schema_version": data["schema_version"],
        "redacted": data["redacted"],
        "report_fields": {k: rf[k] for k in ("incident_summary_auto", "detected_at_first",
                                             "detected_at_last", "affected_asset_ids")},
        "events_total": data["events_total"],
        "events_included": data["events_included"],
        "events_truncated": data["events_truncated"],
        "events": [_pick(e, _EVENT_SCHEMA, path, f"events[{i}]") for i, e in enumerate(events)],
        "active_containments": [_pick(c, _CONTAINMENT_SCHEMA, path, f"active_containments[{i}]")
                                for i, c in enumerate(data["active_containments"])],
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


_LINE_STATUS_LABELS = {
    "legacy": "ハッシュ導入前の行（検証対象外）",
    "legacy_after_chain": "ハッシュのない行がハッシュ付きの行の後にある（異常）",
    "partial": "末尾の書きかけの行（検証対象外）",
    "corrupted": "壊れた・書き換えられた行",
    "chain_break": "前後のつながりが合わない行",
    "head_missing": "先頭の欠落",
}


def _chain_lines(name: str, c: dict[str, Any]) -> list[str]:
    """Status plus every non-ok line count, so lines that were NOT verified
    (legacy, partial) are visible even when the overall status reads ok."""
    out = [f"証跡の改ざん検知 [{name}]: {_vis(c['status'])}（{c['total_lines']} 行を確認）"]
    if c["read_error"]:
        out.append(f"  読み取りエラー: {_vis(c['read_error'])}")
    for st, n in sorted(c["counts"].items()):
        if st != "ok" and n:
            out.append(f"  {_vis(_LINE_STATUS_LABELS.get(st, st))}: {n} 行")
    if c["partial_last_line"] and not c["counts"].get("partial"):
        out.append("  末尾の書きかけの行あり（検証対象外）")
    return out


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
        lines.extend(_chain_lines(name, ce["chain_verification"][key]))
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
    """Zero-dependency HTML — print-to-PDF from any browser (no PDF library added, see design doc §4.2)."""
    body = render_text(doc)
    esc = _esc(body)
    return (
        "<!doctype html><html lang=\"ja\"><head><meta charset=\"utf-8\">"
        "<title>Zee 当局向け報告書</title>"
        "<style>body{font-family:sans-serif;white-space:pre-wrap;"
        "max-width:40em;margin:2em auto;line-height:1.6}</style></head>"
        f"<body>{esc}</body></html>"
    )
