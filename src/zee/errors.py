"""Zee error codes.

Code ranges:
    Z1xx — configuration / validation
    Z2xx — decoy seeding
    Z3xx — watcher (detection)
    Z4xx — responder (containment)
    Z5xx — notifier
    Z6xx — recovery
    Z7xx — containment report export (Z710–Z721: privsep cut daemon, docs/design/privsep.md)
    Z10xx — incident report bundling (police/PPC handoff documents)
    Z8xx — decoy PII dilution (value-dilution dummy records)
    Z9xx — unexpected internal errors

User-reported issues should be traceable from the code alone.
"""

from __future__ import annotations

# Z1xx
Z101_INVALID_ASSET_CONFIG = ("Z101", "資産設定ファイルの形式が正しくありません")
Z102_UNKNOWN_ASSET_ID = ("Z102", "指定された asset_id は資産設定ファイルに存在しません")
Z103_INVALID_RESPONSE_MODE = ("Z103", "response_mode は auto / staged / notify のいずれかを指定してください")
Z104_INVALID_CUT_METHOD = ("Z104", "cut_method は full / egress のいずれかを指定してください")

# Z2xx
Z201_DECOY_PATH_NOT_WRITABLE = ("Z201", "囮ファイルの設置先パスが書き込めません")

# Z3xx
Z301_WATCHER_BACKEND_UNAVAILABLE = ("Z301", "この OS では選択した watcher バックエンドが利用できません")
Z302_DECOY_PATH_NOT_FOUND = ("Z302", "監視対象の囮パスが存在しません")

# Z4xx
Z401_INSUFFICIENT_PRIVILEGE = ("Z401", "遮断に必要な権限（管理者権限）が不足しています")
Z402_CUT_METHOD_NOT_SUPPORTED = ("Z402", "この OS では選択した cut_method が実装されていません")
Z403_INVALID_CONFIDENCE_FOR_CONTAIN = ("Z403", "自動遮断は confidence=high のみで起動可能です")
Z404_CUT_COMMAND_FAILED = ("Z404", "遮断コマンドの実行に失敗しました")

# Z5xx
Z501_LOCAL_NOTIFY_BACKEND_MISSING = ("Z501", "ローカル通知バックエンドが利用できません")
Z502_WEBHOOK_TIMEOUT = ("Z502", "Webhook の送信がタイムアウトしました")
Z503_WEBHOOK_HTTP_ERROR = ("Z503", "Webhook のレスポンスがエラーでした")

# Z6xx
Z601_RESTORE_FAILED = ("Z601", "復旧コマンドの実行に失敗しました")
Z602_RESTORE_TOKEN_REQUIRED = ("Z602", "復旧トークンが必要です。--token または ZEE_RESTORE_TOKEN を指定してください")
Z603_RESTORE_TOKEN_NOT_INITIALIZED = ("Z603", "復旧トークンが未初期化です。`zee init-restore-token` を最初に実行してください")
Z604_RESTORE_TOKEN_INVALID = ("Z604", "復旧トークンが一致しません")
Z606_RESTORE_UNVERIFIED = ("Z606", "復旧後の状態を確認できませんでした（確認に必要なツールが無い等）。遮断が残っている可能性があるため未解決のままにします")
Z605_RESTORE_NO_CUT_RECORD = ("Z605", "遮断記録が無いため通常の復旧を拒否しました。状態を確認のうえ、必要なら --all-interfaces で全面復旧してください")

# Z7xx
Z701_EXPORT_OUTPUT_NOT_WRITABLE = ("Z701", "エクスポート出力先に書き込めません")
Z702_INVALID_TIME_RANGE = ("Z702", "--since / --until の日時形式が不正、または since が until より後です")

# Z710–Z721 — privsep cut daemon (zee privsep ...)
Z710_CUTD_UNREACHABLE = ("Z710", "遮断部（zee privsep daemon）に接続できません。macOS は `sudo launchctl print system/io.github.kamanoi.zee-cutd`、Linux は `systemctl status zee-cutd` で動いているか確認してください")
Z711_CUTD_MALFORMED = ("Z711", "遮断部への要求の形が正しくありません")
Z712_CUTD_PEER_NOT_ALLOWED = ("Z712", "このユーザーは遮断部への要求を許可されていません（--allow-uid に無い uid、または root 専用の操作）")
Z713_CUTD_UNKNOWN_OP = ("Z713", "遮断部が受け付けない要求です（復旧・設定変更・停止は署名付きの challenge／submit だけ）")
Z714_CUTD_SIGNATURE_REFUSED = ("Z714", "署名付きの要求が拒否されました（期限切れ・照合コード違い・署名不正・再送・未登録の鍵など。新しい challenge からやり直してください）")
Z715_CUTD_POLICY_REFUSED = ("Z715", "遮断部の方針または引数の検査で拒否されました（自動遮断が OFF・dry_run・未知の資産など）")
Z716_CUTD_INTERNAL = ("Z716", "遮断部の内部エラー、または遮断・復旧の処理がエラーを返しました（詳細は返答の error）")
Z717_CUTD_RATE_LIMITED = ("Z717", "署名請求の頻度の上限（1分に10件）を超えました。少し待ってからやり直してください")
Z718_CUTD_OPERATION_FAILED = ("Z718", "署名は受け付けられましたが、操作そのものが失敗しました（詳細は返答の detail）")
Z719_PRIVSEP_REQUEST_FILE = ("Z719", "--request／--signature／--public-key のファイルが無い・読めない・形が正しくありません")
Z720_CUTD_RESULT_UNKNOWN = ("Z720", "要求は遮断部に届きましたが返事が得られませんでした。実行済みの可能性があります。`zee privsep status`（unresolved・auto）で状態を確かめてから次の操作をしてください")
Z721_CUTD_START_REFUSED = ("Z721", "遮断部の起動を拒否しました（Python・zee のコード・ソケットの置き場所を root 以外が書き換えられる、または --group が存在しない）。手順書 docs/maintenance/privsep_install.md の配置を確認してください")

# Z10xx
Z1001_UNKNOWN_RECIPIENT = ("Z1001", "--recipient は police / ppc のいずれかを指定してください")
Z1004_EXPORT_FILE_REQUIRED = ("Z1004", "--export-json のファイルが zee export が書くスキーマと一致しない、または読めません")
Z1005_OUTPUT_COLLIDES_WITH_INPUT = ("Z1005", "--out の出力先が --export-json の入力ファイルと同じです（--force でも上書きしません）")
# Z8xx
Z801_NO_ELIGIBLE_PARCEL = ("Z801", "公園・河川区域に完全に含まれる地番が1件も見つかりませんでした（fail-closed）")
Z802_EMAIL_DOMAIN_REQUIRED = ("Z802", "--email-mode=user-domain には --email-domain の指定が必要です")
Z803_MISSING_LAYER2_INPUT = ("Z803", "--layer に real-nonresidential/both を指定する場合は --parcels と --public-land の両方が必要です")
Z804_CRS_MISMATCH = ("Z804", "地番データと公有地データの座標系(crs)が一致しません")
Z805_EMPTY_TOWN_MASTER = ("Z805", "町字マスターが空です。架空町名の非実在確認ができないため生成を拒否します")
Z806_WEAK_SEED = ("Z806", "--seed が短すぎます（最低16文字）。弱いseedはHMAC台帳の安全性を損ないます")
Z807_INVALID_COUNT = ("Z807", "--count は1以上の整数を指定してください")
Z808_OUTPUT_EXISTS = ("Z808", "出力先に records.csv / ledger.jsonl が既に存在します。上書きしません。別の --out を指定してください")
Z809_ADDRESS_POOL_EXHAUSTED = ("Z809", "重複しない住所の組み合わせが尽きました。--count を減らすか、入力データ（適格な地番・町字マスター）を増やしてください")

# Z9xx
Z901_INTERNAL = ("Z901", "予期しない内部エラー")


class ZeeError(Exception):
    """Zee internal exception carrying an error code and human description."""

    def __init__(self, code_def: tuple[str, str], detail: str = "") -> None:
        self.code, self.message = code_def
        self.detail = detail
        full_msg = f"[{self.code}] {self.message}"
        if detail:
            full_msg += f" — {detail}"
        super().__init__(full_msg)
