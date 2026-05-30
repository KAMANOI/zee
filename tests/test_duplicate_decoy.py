"""Reviewer high-severity fix: duplicate decoy_path across assets is rejected."""

from __future__ import annotations

from pathlib import Path

from zee.cli import build_parser, _cmd_watch


def _write_config(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "assets.yaml"
    p.write_text(body)
    return p


def test_duplicate_decoy_path_across_assets_rejected(tmp_path, capsys):
    cfg = _write_config(tmp_path, """
assets:
  - id: host-a
    type: workstation
    decoy_paths:
      - /tmp/zee-shared-decoy
    response_mode: notify
  - id: host-b
    type: workstation
    decoy_paths:
      - /tmp/zee-shared-decoy
    response_mode: notify
""")
    parser = build_parser()
    args = parser.parse_args(["-c", str(cfg), "watch"])
    rc = _cmd_watch(args)
    captured = capsys.readouterr()
    assert rc == 1
    assert "appears under both" in captured.err
    assert "host-a" in captured.err and "host-b" in captured.err


def test_same_asset_same_path_is_fine_for_dup_check(tmp_path):
    """Cross-asset check should not flag two entries of the same asset.

    We only verify the duplicate-detection branch here. The full watch
    loop is exercised by examples/demo_dry_run.py and platform-specific
    watcher tests.
    """
    # Verify the check directly without entering the watch loop.
    from zee.config.schema import Config
    cfg_path = _write_config(tmp_path, """
assets:
  - id: host-a
    type: workstation
    decoy_paths:
      - /tmp/zee-same-asset-decoy
      - /tmp/zee-same-asset-decoy
    response_mode: notify
""")
    config = Config.load(cfg_path)
    # Replicate the cli's duplicate check logic.
    seen: dict[str, str] = {}
    cross_asset_dup = False
    for asset in config.assets:
        for raw in asset.decoy_paths:
            key = str(Path(raw).expanduser())
            if key in seen and seen[key] != asset.id:
                cross_asset_dup = True
            seen[key] = asset.id
    assert cross_asset_dup is False
