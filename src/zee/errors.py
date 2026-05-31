"""Zee error codes.

Code ranges:
    Z1xx — configuration / validation
    Z2xx — decoy seeding
    Z3xx — watcher (detection)
    Z4xx — responder (containment)
    Z5xx — notifier
    Z6xx — recovery
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
