"""Cut-state log behaviour (spec L2, v0.3)."""

from __future__ import annotations

import json
import os
import stat
import sys

import pytest

from zee.telemetry.cut_state import CutStateLog

posix_only = pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX permission bits do not survive on NTFS; Windows uses ACLs",
)


def test_record_and_latest_round_trip(tmp_path):
    log = CutStateLog(path=tmp_path / "cut_state.jsonl")
    log.record_cut(
        asset_id="host-a",
        method="full",
        platform="darwin",
        modified=["Wi-Fi", "Ethernet"],
    )
    latest = log.latest_unresolved_for("host-a")
    assert latest is not None
    assert latest.asset_id == "host-a"
    assert latest.method == "full"
    assert latest.platform == "darwin"
    assert latest.modified == ("Wi-Fi", "Ethernet")


def test_mark_resolved_clears_latest(tmp_path):
    log = CutStateLog(path=tmp_path / "cut_state.jsonl")
    log.record_cut(
        asset_id="host-a", method="full", platform="darwin",
        modified=["Wi-Fi"],
    )
    log.mark_resolved("host-a")
    assert log.latest_unresolved_for("host-a") is None


def test_second_cut_after_resolved_is_the_active_one(tmp_path):
    log = CutStateLog(path=tmp_path / "cut_state.jsonl")
    log.record_cut(asset_id="host-a", method="full", platform="darwin",
                   modified=["Wi-Fi"])
    log.mark_resolved("host-a")
    log.record_cut(asset_id="host-a", method="egress", platform="darwin",
                   modified=["__zee_pfctl_egress_anchor__"])
    latest = log.latest_unresolved_for("host-a")
    assert latest is not None
    assert latest.method == "egress"
    assert latest.modified == ("__zee_pfctl_egress_anchor__",)


def test_other_asset_does_not_pollute(tmp_path):
    log = CutStateLog(path=tmp_path / "cut_state.jsonl")
    log.record_cut(asset_id="host-a", method="full", platform="darwin",
                   modified=["Wi-Fi"])
    log.record_cut(asset_id="host-b", method="egress", platform="linux",
                   modified=["__zee_nft_egress_table__"])
    a = log.latest_unresolved_for("host-a")
    b = log.latest_unresolved_for("host-b")
    assert a is not None and a.modified == ("Wi-Fi",)
    assert b is not None and b.modified == ("__zee_nft_egress_table__",)


def test_missing_file_returns_none(tmp_path):
    log = CutStateLog(path=tmp_path / "nope.jsonl")
    assert log.latest_unresolved_for("host-a") is None


@posix_only
def test_file_is_owner_only(tmp_path):
    log = CutStateLog(path=tmp_path / "state" / "cut_state.jsonl")
    log.record_cut(asset_id="host-a", method="full", platform="darwin",
                   modified=["Wi-Fi"])
    mode = stat.S_IMODE(os.stat(log.path).st_mode)
    assert mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH) == 0


def test_malformed_line_does_not_break_walk(tmp_path):
    path = tmp_path / "cut_state.jsonl"
    path.write_text(
        "this is not json\n"
        + json.dumps({
            "type": "cut",
            "asset_id": "host-a",
            "cut_at": "2026-05-31T00:00:00+00:00",
            "method": "full",
            "platform": "darwin",
            "modified": ["Wi-Fi"],
        })
        + "\n",
        encoding="utf-8",
    )
    log = CutStateLog(path=path)
    latest = log.latest_unresolved_for("host-a")
    assert latest is not None
    assert latest.modified == ("Wi-Fi",)
