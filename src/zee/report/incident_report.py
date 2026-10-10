"""Bundle Zee's own records into a document a human can hand to police or
to the Personal Information Protection Commission (PPC).

This module never submits, uploads, or sends anything — it has no
import of ``urllib``, ``http.client``, ``socket``, ``smtplib``,
``requests``, or ``zee.notifier`` (enforced by
tests/test_incident_report.py::test_no_network_imports). It only reads
files other Zee commands already wrote (``zee export`` JSON output) or
numbers the operator already computed elsewhere (dilution ledger
match counts) — see docs/design/incident-report.md §1. The ledger file
and seed used to tell real records from dummy ones are never read by
this module (§4.2 of that doc): only the two integers the operator
already derived from them are accepted.

Bundling an "incident" is the operator's call, not an automatic one:
Zee does not record a connection source for file/canary-token events
(see docs/containment-report-mapping.md §5), so there is nothing here
to cluster on beyond what the operator already scoped with
`zee export --since/--until` and the specific canary-hit files they
choose to attach (§2 of the design doc).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from ..errors import (
    Z1001_UNKNOWN_RECIPIENT,
    Z1002_INVALID_CANARY_HITS_FILE,
    Z1003_DILUTION_COUNT_INCONSISTENT,
    Z1004_EXPORT_FILE_REQUIRED,
    ZeeError,
)
from .recipients import BY_NAME, Recipient

SCHEMA_VERSION = "1"

_OPERATOR_FILLS_IN = "利用者が記入"
_ZEE_DOES_NOT_RECORD = "不明（Zeeはこの情報を記録しません）"
_HEURISTIC_NOTE = (
    "この事案の範囲（期間・添付した照会型カナリアのログ・ダミー混入の集計）は"
    "利用者が指定したものです。Zee が接続元やトークンから自動的に同一主体と"
    "判定したものではありません（Zeeは接続元IPを記録しないため、自動判定の"
    "根拠自体を持ちません）。"
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


@dataclass(frozen=True)
class DilutionSummary:
    leaked_total: int
    dummy_matched: int

    def __post_init__(self) -> None:
        if self.leaked_total < 0 or self.dummy_matched < 0 or self.dummy_matched > self.leaked_total:
            raise ZeeError(
                Z1003_DILUTION_COUNT_INCONSISTENT,
                f"leaked_total={self.leaked_total} dummy_matched={self.dummy_matched}",
            )

    @property
    def real_upper_bound(self) -> int:
        return self.leaked_total - self.dummy_matched


_SUPPORTED_EXPORT_SCHEMA_VERSIONS = {"1"}


def load_export(path: Path) -> dict[str, Any]:
    """Read a `zee export --out <prefix>` JSON file and sanity-check its shape."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ZeeError(Z1004_EXPORT_FILE_REQUIRED, f"{path}: {e}") from e
    if (
        not isinstance(data, dict)
        or data.get("schema_version") not in _SUPPORTED_EXPORT_SCHEMA_VERSIONS
        or not isinstance(data.get("report_fields"), dict)
    ):
        raise ZeeError(
            Z1004_EXPORT_FILE_REQUIRED,
            f"{path} は zee export の出力（対応する schema_version・dict の report_fields を"
            "含むJSON）ではありません",
        )
    return data


def _parse_ts(ts: Any, context: str) -> datetime:
    if not isinstance(ts, str):
        raise ZeeError(Z1002_INVALID_CANARY_HITS_FILE, f"{context}: 'ts' は文字列（ISO8601）である必要があります")
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError as e:
        raise ZeeError(Z1002_INVALID_CANARY_HITS_FILE, f"{context}: 'ts'={ts!r} をISO8601として解析できません: {e}") from e
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def load_canary_hits(paths: list[Path]) -> list[dict[str, Any]]:
    """Read one or more canary-hit JSON Lines logs (one JSON object per line)."""
    hits: list[dict[str, Any]] = []
    for p in paths:
        try:
            lines = Path(p).read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as e:
            raise ZeeError(Z1002_INVALID_CANARY_HITS_FILE, f"{p}: {e}") from e
        for i, raw in enumerate(lines, start=1):
            line = raw.strip()
            if not line:
                continue
            context = f"{p}:{i}"
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as e:
                raise ZeeError(Z1002_INVALID_CANARY_HITS_FILE, f"{context}: {e}") from e
            if not isinstance(rec, dict) or not isinstance(rec.get("token"), str) or not rec.get("token"):
                raise ZeeError(
                    Z1002_INVALID_CANARY_HITS_FILE,
                    f"{context}: 'token'（空でない文字列）を含む1行1JSONの形式ではありません",
                )
            _parse_ts(rec.get("ts"), context)  # validates; original string is kept for display
            hits.append(rec)
    return hits


def _canary_summary(hits: list[dict[str, Any]]) -> dict[str, Any]:
    if not hits:
        return {"count": 0, "first_seen": None, "last_seen": None, "unique_tokens": 0, "hits": []}
    ordered = sorted(hits, key=lambda h: _parse_ts(h["ts"], "canary_hit"))
    return {
        "count": len(hits),
        "first_seen": ordered[0]["ts"],
        "last_seen": ordered[-1]["ts"],
        "unique_tokens": len({h["token"] for h in hits}),
        "hits": hits,
    }


def build_incident_report(
    *,
    export: dict[str, Any],
    recipient: str,
    canary_hits: Optional[list[dict[str, Any]]] = None,
    dilution: Optional[DilutionSummary] = None,
    incident_label: Optional[str] = None,
) -> dict[str, Any]:
    """Assemble the incident report document. Writes nothing."""
    if recipient not in BY_NAME:
        raise ZeeError(Z1001_UNKNOWN_RECIPIENT, repr(recipient))
    rf = export.get("report_fields", {})

    doc: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "recipient": recipient,
        "incident_label": incident_label or _OPERATOR_FILLS_IN,
        "bundling_note": _HEURISTIC_NOTE,
        "containment_export": {
            "incident_summary_auto": rf.get("incident_summary_auto", ""),
            "detected_at_first": rf.get("detected_at_first"),
            "detected_at_last": rf.get("detected_at_last"),
            "affected_asset_ids": rf.get("affected_asset_ids", []),
            "events_total": export.get("events_total", 0),
            "events_included": export.get("events_included", 0),
            "events_truncated": export.get("events_truncated", False),
            "events": export.get("events", []),
            "active_containments": export.get("active_containments", []),
            "chain_verification": export.get("chain_verification", {}),
        },
        "query_canary": _canary_summary(canary_hits or []),
        "submission": {
            "note": (
                "この文書は提出用の材料です。Zee はここからの送信・提出を行いません。"
                "提出は利用者ご自身で行ってください。"
            ),
        },
    }

    if dilution is not None:
        doc["dilution"] = {
            "leaked_total": dilution.leaked_total,
            "dummy_matched": dilution.dummy_matched,
            "real_upper_bound": dilution.real_upper_bound,
            "note": (
                "台帳（ledger）・シードはこの報告書の作成経路に含まれません。"
                "ダミー判定の明細は別途提示可能です。"
            ),
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
            "1 概要": rf.get("incident_summary_auto", "") or _OPERATOR_FILLS_IN,
            "2 漏えい等が発生し、又は発生したおそれがある個人データの項目": _ZEE_DOES_NOT_RECORD,
            "3 漏えい等が発生し、又は発生したおそれがある個人データに係る本人の数": (
                f"ダミー判定後の実在本人数は{doc['dilution']['real_upper_bound']}件以下（上限の補正材料。最終記入は利用者）"
                if dilution is not None else _OPERATOR_FILLS_IN
            ),
            "4 原因": (
                "囮・照会型カナリアの作動記録あり（不正アクセス等の材料。該当性の判断は利用者）"
                if (export.get("events_total", 0) or doc["query_canary"]["count"])
                else _OPERATOR_FILLS_IN
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
    lines: list[str] = ["# Zee 当局向け報告書（事案まとめ）", f"生成日時: {doc['generated_at']}", f"事案ラベル: {doc['incident_label']}", ""]
    lines.append(doc["bundling_note"])
    lines.append("")

    ce = doc["containment_export"]
    lines.append("## 封じ込め証跡（zee export 由来）")
    lines.append(ce["incident_summary_auto"] or "（記録なし）")
    lines.append(f"検知期間: {ce['detected_at_first'] or '不明'} 〜 {ce['detected_at_last'] or '不明'}")
    lines.append(f"対象資産: {', '.join(ce['affected_asset_ids']) or '（なし）'}")
    lines.append(
        f"検知イベント件数: {ce['events_total']}"
        f"（この文書のJSONに{ce['events_included']}件を収録"
        + ("・新しい順に一部のみ" if ce["events_truncated"] else "")
        + "。個別イベントの時刻・操作種別・検知元は <out>.json の containment_export.events を参照）"
    )
    lines.append(f"解除されていない遮断記録: {len(ce['active_containments'])} 件")
    for name, key in (("events.jsonl", "events_jsonl"), ("metrics.jsonl", "metrics_jsonl")):
        c = ce["chain_verification"].get(key, {})
        lines.append(f"証跡の改ざん検知 [{name}]: {c.get('status', '不明')}")
    lines.append("")

    qc = doc["query_canary"]
    lines.append("## 照会型カナリア（任意・添付があれば集計）")
    if qc["count"]:
        lines.append(
            f"発火件数: {qc['count']}（ユニークトークン {qc['unique_tokens']}、"
            f"{qc['first_seen']} 〜 {qc['last_seen']}）"
        )
        lines.append(
            "個別ヒット（時刻・接続元・トークン。hostname型はDNSリゾルバのIPである"
            "可能性が高い点に注意 — query-canary.md §2.1）:"
        )
        for h in qc["hits"]:
            lines.append(f"- {h['ts']} remote_ip={h.get('remote_ip', '不明')} token={h['token']}")
    else:
        lines.append("添付なし")
    lines.append("")

    if "dilution" in doc:
        d = doc["dilution"]
        lines.append("## ダミー混入（任意・集計のみ）")
        lines.append(f"漏えいデータ {d['leaked_total']} 件中 {d['dummy_matched']} 件がダミー判定")
        lines.append(f"実在本人数の上限（補正材料）: {d['real_upper_bound']} 件以下")
        lines.append(d["note"])
        lines.append("")

    from .recipients import POLICE_PHONE_CONSULT

    if doc["recipient"] == "police":
        lines.append("## 報告項目（警察向け・任意通報）")
        for k, v in doc["police_fields"].items():
            if k != "note":
                lines.append(f"- {k}: {v}")
        lines.append(doc["police_fields"]["note"])
    else:
        lines.append("## 法定報告事項（個人情報保護委員会向け・施行規則第8条）")
        for k in _STATUTORY_PPC_ITEMS_ORDER:
            lines.append(f"- {k}: {doc['ppc_statutory_items'][k]}")
        lines.append(doc["ppc_statutory_items"]["note"])
    lines.append("")

    # 代表指示（2026-10-09）：データ末尾に警視庁サイバー窓口とPPC窓口の両方を入れる。
    # 本文（上の報告項目）は --recipient で選んだ1件分のみ。末尾の参照窓口は常に
    # 両方を列挙し、警察の任意通報とPPCの法定報告（個人情報保護法26条）が
    # 別の手続き・別の期限であることを明記する（混同しない・claude.ai補足6）。
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
