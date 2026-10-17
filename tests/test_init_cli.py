"""`zee init`: starter assets.toml for installs without a clone."""

import os
import stat
import sys
from pathlib import Path

import pytest

from zee.cli import main
from zee.config.schema import Config

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "assets.example.toml"


def test_init_writes_loadable_observe_only_config(tmp_path, capsys):
    target = tmp_path / "assets.toml"
    assert main(["-c", str(target), "init"]) == 0
    cfg = Config.load(target)
    assert cfg.dry_run is True
    assert len(cfg.assets) == 1
    a = cfg.assets[0]
    assert a.id and a.response_mode == "notify"
    if sys.platform != "win32":
        assert stat.S_IMODE(os.stat(target).st_mode) == 0o600
    assert "zee init-restore-token" in capsys.readouterr().err


def test_init_matches_example_defaults(tmp_path):
    """Keep the embedded template in step with examples/assets.example.toml."""
    target = tmp_path / "assets.toml"
    main(["-c", str(target), "init"])
    ex = Config.load(EXAMPLE)
    got = Config.load(target)
    assert got.dry_run == ex.dry_run is True
    ex_dirs = {Path(p).parent.as_posix() for a in ex.assets for p in a.decoy_paths}
    got_dirs = {Path(p).parent.as_posix() for a in got.assets for p in a.decoy_paths}
    assert got_dirs == ex_dirs == {"~/.local/share/zee-decoys"}
    assert {a.response_mode for a in ex.assets} == {a.response_mode for a in got.assets}


def test_init_refuses_existing_file_untouched(tmp_path, capsys):
    target = tmp_path / "assets.toml"
    target.write_bytes(b"mine")
    assert main(["-c", str(target), "init"]) == 1
    assert target.read_bytes() == b"mine"
    err = capsys.readouterr().err
    assert "Z105" in err and "discussions" not in err


@pytest.mark.skipif(sys.platform == "win32", reason="symlink needs privilege on Windows")
def test_init_refuses_dangling_symlink(tmp_path):
    target = tmp_path / "assets.toml"
    victim = tmp_path / "elsewhere"
    target.symlink_to(victim)
    assert main(["-c", str(target), "init"]) == 1
    assert not victim.exists()


def test_init_missing_folder_is_z106(tmp_path, capsys):
    assert main(["-c", str(tmp_path / "nope" / "assets.toml"), "init"]) == 1
    assert "Z106" in capsys.readouterr().err


def test_init_race_after_check_reports_z105(tmp_path, capsys, monkeypatch):
    import zee.cli as cli
    target = tmp_path / "assets.toml"
    real = cli._write_private_files

    def racer(outputs, force):
        target.write_bytes(b"other")
        return real(outputs, force)

    monkeypatch.setattr(cli, "_write_private_files", racer)
    assert main(["-c", str(target), "init"]) == 1
    assert target.read_bytes() == b"other"
    assert "Z105" in capsys.readouterr().err


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX quoting")
def test_init_next_step_quotes_path(tmp_path, capsys):
    target = tmp_path / "my dir" / "a.toml"
    target.parent.mkdir()
    assert main(["-c", str(target), "init"]) == 0
    assert f"zee -c '{target}' watch" in capsys.readouterr().err
