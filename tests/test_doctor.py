"""`zee doctor`: read-only self-check."""

import io
import os
import sys
from pathlib import Path

import pytest

from zee import doctor
from zee.cli import main

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setenv("HOME", str(h))
    monkeypatch.setenv("USERPROFILE", str(h))
    monkeypatch.setenv("XDG_STATE_HOME", str(h / "state"))
    monkeypatch.delenv("ZEE_CANARY_BASE_URL", raising=False)
    return h


def _run(cfg, ps=lambda: []):
    buf = io.StringIO()
    rc = doctor.run(cfg, ps=ps, out=buf)
    return rc, buf.getvalue()


def _token(home, mode=0o600):
    d = home / ".zee"
    d.mkdir(mode=0o700, exist_ok=True)
    t = d / "restore_token"
    t.write_text("x\n")
    os.chmod(t, mode)


def _write(cfg, body):
    cfg.write_text(body)
    os.chmod(cfg, 0o600)


def test_no_config_fails_and_points_to_init(home):
    rc, out = _run(home / "assets.toml")
    assert rc == 1
    assert "[FAIL] config" in out and "zee init" in out


def test_after_init_no_token_is_warn_only(home):
    cfg = home / "assets.toml"
    assert main(["-c", str(cfg), "init"]) == 0
    rc, out = _run(cfg)
    assert rc == 0, out
    assert "[FAIL]" not in out
    assert "[WARN] restore token" in out and "zee init-restore-token" in out
    assert "observe only" in out
    assert "[WARN] watch" in out  # injected empty process list


@posix_only
def test_loose_token_fails(home):
    cfg = home / "assets.toml"
    main(["-c", str(cfg), "init"])
    _token(home, 0o644)
    rc, out = _run(cfg)
    assert rc == 1 and "[FAIL] restore token" in out


@posix_only
def test_token_value_is_never_printed(home):
    cfg = home / "assets.toml"
    main(["-c", str(cfg), "init"])
    _token(home)
    (home / ".zee" / "restore_token").write_text("SECRET-VALUE\n")
    rc, out = _run(cfg)
    assert "[OK] restore token" in out and "SECRET-VALUE" not in out


def test_duplicate_decoy_fails(home):
    cfg = home / "assets.toml"
    _write(cfg, """
[[assets]]
id = "a"
decoy_paths = ["~/z/x.decoy"]
[[assets]]
id = "b"
decoy_paths = ["~/z/x.decoy"]
""")
    rc, out = _run(cfg)
    assert rc == 1 and "under both 'a' and 'b'" in out


def test_synced_folder_warns(home):
    cfg = home / "assets.toml"
    _write(cfg, '[[assets]]\nid = "a"\ndecoy_paths = ["~/Documents/x.decoy"]\n')
    rc, out = _run(cfg)
    assert "[WARN] decoy" in out and "'Documents'" in out


@posix_only
def test_armed_without_root_warns(home, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    cfg = home / "assets.toml"
    _write(cfg, 'dry_run = false\n[[assets]]\nid = "a"\nresponse_mode = "auto"\n'
                'decoy_paths = ["~/z/x.decoy"]\n')
    rc, out = _run(cfg)
    assert "automatic cut is ON" in out
    assert "[WARN] cut privileges" in out


def test_watch_detection():
    assert doctor._looks_like_watch("/u/.local/bin/python /u/.local/bin/zee -c a.toml watch")
    assert doctor._looks_like_watch("python -m zee.cli watch")
    assert not doctor._looks_like_watch("/u/.local/bin/zee -c watch.toml doctor")
    assert not doctor._looks_like_watch("vim watch")


def test_bad_canary_url_fails(home, monkeypatch):
    monkeypatch.setenv("ZEE_CANARY_BASE_URL", "http://example.invalid/r")
    cfg = home / "assets.toml"
    main(["-c", str(cfg), "init"])
    rc, out = _run(cfg)
    assert rc == 1 and "[FAIL] canary" in out


def test_doctor_changes_nothing(home):
    cfg = home / "assets.toml"
    main(["-c", str(cfg), "init"])
    _token(home)
    decoy_dir = home / ".local" / "share" / "zee-decoys"
    decoy_dir.mkdir(parents=True)
    (decoy_dir / ".env").write_text("d")
    (home / "state" / "zee").mkdir(parents=True)

    def snap():
        return {p: (p.read_bytes() if p.is_file() else None, p.stat().st_mtime_ns)
                for p in sorted(home.rglob("*"))}

    before = snap()
    _run(cfg)
    assert main(["-c", str(cfg), "doctor"]) in (0, 1)
    assert snap() == before


# --- Codex review 1 regressions -------------------------------------------

@posix_only
def test_config_pointing_at_token_is_not_read(home):
    _token(home)
    (home / ".zee" / "restore_token").write_text("SECRET-VALUE\n")
    link = home / "assets.toml"
    link.symlink_to(home / ".zee" / "restore_token")
    rc, out = _run(link)
    assert rc == 1 and "restore token file; not read" in out
    assert "SECRET-VALUE" not in out


@pytest.mark.parametrize("body", [
    b'[[assets]]\nid = true\ndecoy_paths = ["~/z/x"]\n',
    b'[[assets]]\nid = "a"\ndecoy_paths = [123]\n',
    b'[[assets]]\nid = "a"\ndecoy_paths = "~/z/x"\n',
    b'\xff\xfe not utf-8',
])
def test_malformed_config_is_fail_not_crash(home, body):
    cfg = home / "assets.toml"
    cfg.write_bytes(body)
    rc, out = _run(cfg)
    assert rc == 1 and "[FAIL] config" in out and "summary:" in out


def test_numeric_asset_id_still_loads(home):
    # v0.14.0 accepted `id = 1`; upgrading must not stop such a watch.
    from zee.config.schema import Config
    cfg = home / "assets.toml"
    cfg.write_bytes(b'[[assets]]\nid = 1\ndecoy_paths = ["~/z/x"]\n')
    assert Config.load(cfg).assets[0].id == "1"


def test_next_steps_put_c_before_the_subcommand(home):
    rc, out = _run(home / "missing.toml")
    assert "zee -c PATH doctor" in out and "doctor -c" not in out


def test_canary_same_rule_as_watch(home, monkeypatch):
    monkeypatch.setenv("ZEE_CANARY_BASE_URL", "https")  # no scheme separator: watch refuses
    rc, out = _run(home / "missing.toml")
    assert "[FAIL] canary" in out


def test_state_dir_that_is_a_file_fails(home):
    (home / "state").mkdir()
    (home / "state" / "zee").write_text("not a dir")
    rc, out = _run(home / "missing.toml")
    assert "[FAIL] state dir" in out


@posix_only
def test_privsep_path_that_is_not_a_socket_fails(home, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    fake = home / "cutd.sock"
    fake.write_text("")
    cfg = home / "assets.toml"
    _write(cfg, f'dry_run = false\n[privsep]\nsocket = "{fake}"\n'
                '[[assets]]\nid = "a"\nresponse_mode = "auto"\ndecoy_paths = ["~/z/x"]\n')
    rc, out = _run(cfg)
    assert rc == 1 and "not a socket" in out


# --- Codex review 2 regressions -------------------------------------------

@posix_only
def test_hardlink_to_token_is_not_read(home):
    _token(home)
    (home / ".zee" / "restore_token").write_text("SECRET-VALUE\n")
    os.link(home / ".zee" / "restore_token", home / "assets.toml")
    rc, out = _run(home / "assets.toml")
    assert rc == 1 and "not read" in out and "SECRET-VALUE" not in out


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs mkfifo")
def test_fifo_config_does_not_hang(home):
    fifo = home / "assets.toml"
    os.mkfifo(fifo)
    rc, out = _run(fifo)
    assert rc == 1 and "not a regular file" in out


@pytest.mark.parametrize("decoy", [
    pytest.param("~zee_no_such_user_xyz/x", marks=posix_only),  # ntpath guesses ~user instead
    "/tmp/a\\u0000b",
])
def test_unusable_decoy_path_is_z101(home, decoy):
    cfg = home / "assets.toml"
    _write(cfg, f'[[assets]]\nid = "a"\ndecoy_paths = ["{decoy}"]\n')
    rc, out = _run(cfg)
    assert rc == 1 and "Z101" in out


def test_output_survives_a_narrow_encoding(home):
    raw = io.BytesIO()
    out = io.TextIOWrapper(raw, encoding="cp1252")
    rc = doctor.run(home / "missing.toml", ps=lambda: ["\u732b zee watch"], out=out)
    out.flush()
    assert rc == 1 and b"-> next" in raw.getvalue()


# --- Codex review 3 regressions -------------------------------------------

def test_token_directory_is_not_ok(home):
    (home / ".zee" / "restore_token").mkdir(parents=True)
    rc, out = _run(home / "missing.toml")
    assert "[FAIL] restore token" in out and "not a regular file" in out


def test_state_dir_discovery_error_is_reported(home, monkeypatch):
    def boom():
        raise PermissionError("denied")
    monkeypatch.setattr(doctor, "default_log_dir", boom)
    rc, out = _run(home / "missing.toml")
    assert "[FAIL] state dir" in out and "summary:" in out


# --- v0.15.0 release review regressions -------------------------------------

@pytest.mark.parametrize("decoy", [
    pytest.param("~zee_no_such_user_xyz/x", marks=posix_only),
    "/tmp/a\\u0000b",
])
def test_stale_decoy_path_still_loads_for_restore_but_not_watch(home, decoy):
    # restore / cut only load the config; a decoy path that went stale after a
    # cut must not stop the restore (v0.14.0 behaviour). watch / doctor refuse.
    from zee.config.schema import Config, duplicate_decoys
    from zee.errors import ZeeError
    cfg = home / "assets.toml"
    _write(cfg, f'[[assets]]\nid = "a"\ndecoy_paths = ["{decoy}"]\n')
    loaded = Config.load(cfg)
    with pytest.raises(ZeeError) as e:
        duplicate_decoys(loaded)
    assert "Z101" in str(e.value) or e.value.code == "Z101"


def test_watch_command_lines_are_not_echoed(home):
    line = "/u/bin/zee restore watch --token SECRET-VALUE"
    rc, out = _run(home / "missing.toml", ps=lambda: [line])
    assert "process(es) that look like" in out and "SECRET-VALUE" not in out
