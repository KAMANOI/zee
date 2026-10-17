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
    assert rc == 1 and "is the restore token file" in out
    assert "SECRET-VALUE" not in out


@pytest.mark.parametrize("body", [
    b'[[assets]]\nid = 1\ndecoy_paths = ["~/z/x"]\n',
    b'[[assets]]\nid = "a"\ndecoy_paths = [123]\n',
    b'\xff\xfe not utf-8',
])
def test_malformed_config_is_fail_not_crash(home, body):
    cfg = home / "assets.toml"
    cfg.write_bytes(body)
    rc, out = _run(cfg)
    assert rc == 1 and "[FAIL] config" in out and "summary:" in out


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
