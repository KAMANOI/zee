"""Reference contact data for the two reporting lanes.

Kept as data, not inlined in templates, so a stale phone number or URL
is a one-line diff instead of a prose edit. ``as_of`` is the date this
entry was last checked against a primary source (see
docs/design/incident-report.md §3); the operator is told to re-check
before relying on it, not just told once.

2026-10-09: a secondary listing gave "03-6457-9685" for the PPC phone
contact. Two independent fetches of ppc.go.jp only turned up
03-6457-9680. We use the number we could verify and note the
discrepancy here and in the design doc.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Recipient:
    name: str
    agency: str
    url: str
    phone: str
    hours: str
    as_of: str
    note: str


POLICE = Recipient(
    name="police",
    agency="警察庁 サイバー事案に関する通報・相談・情報提供窓口",
    url="https://www.npa.go.jp/bureau/cyber/soudan.html",
    phone="（電話相談は都内法人の場合は警視庁サイバー犯罪相談窓口。下記参照）",
    hours="（オンライン受付自体の受付時間は未確認。時間外・土日祝の電話相談は翌執務日以降）",
    as_of="2026-10-09",
    note=(
        "入力項目（発生日時・被害内容等の固定フィールド名）はトップページに列挙がなく未確認。"
        "e-Gov電子申請システム経由、氏名とメールアドレスで本人確認後、管轄の都道府県警察・"
        "警察署を選択して詳細を送信する形式（確認済み）。生命・身体に関わる緊急事案は110番。"
    ),
)

POLICE_PHONE_CONSULT = Recipient(
    name="police_phone",
    agency="警視庁 サイバー犯罪に関する電話相談窓口（都内法人向け）",
    url="https://www.keishicho.metro.tokyo.lg.jp/kurashi/cyber/sodan_tsuho/cyber_madoguchi.html",
    phone="（ページ記載の相談専用番号。本書では番号そのものの転記はせず、上記URLを確認する前提とする）",
    hours="平日 午前8時30分〜午後5時15分（平日の執務時間外・土曜・日曜・祝日・12/29〜1/3は翌執務日以降の受付）",
    as_of="2026-10-09",
    note="電話相談時の準備物の一覧はページ本文に記載がなく未確認。緊急事案は110番。",
)

PPC = Recipient(
    name="ppc",
    agency="個人情報保護委員会 個人データ漏えい等報告窓口（個人情報保護法26条・施行規則第8条）",
    url="https://roueihoukoku.ppc.go.jp/incident/",
    phone="03-6457-9680",
    hours="未確認",
    as_of="2026-10-09",
    note=(
        "速報は「速やかに」（条文上の日数指定なし）。確報は知った日から30日以内、"
        "ただし不正アクセス等（施行規則第7条第3号類型）の場合は60日以内。"
        "どちらが適用されるかは利用者が判断する。"
    ),
)

BY_NAME = {"police": POLICE, "ppc": PPC}
