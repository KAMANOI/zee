"""Allowlist file loading, permission check, lookup (spec §C)."""

from __future__ import annotations

import json
import os
import stat
import sys

import pytest

from zee.policy.allowlist import Allowlist

posix_only = pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX permission bits do not survive on NTFS; Windows uses ACLs",
)


def test_in_memory_exe_path_match():
    a = Allowlist(exe_paths={"/usr/bin/duplicacy"})
    assert a.is_protected(exe_path="/usr/bin/duplicacy") is True
    assert a.is_protected(exe_path="/usr/bin/curl") is False


def test_process_name_fallback():
    a = Allowlist(process_names={"Time Machine Helper"})
    assert a.is_protected(proc_name="Time Machine Helper") is True
    assert a.is_protected(proc_name="curl") is False


def test_ip_cidr_match():
    a = Allowlist(ip_cidrs=["10.0.0.0/8", "192.168.1.10/32"])
    assert a.is_protected(ip="10.4.5.6") is True
    assert a.is_protected(ip="192.168.1.10") is True
    assert a.is_protected(ip="8.8.8.8") is False
    assert a.is_protected(ip="not-an-ip") is False


def test_load_from_secure_file(tmp_path):
    path = tmp_path / "allowlist.json"
    path.write_text(json.dumps({
        "exe_paths": ["/usr/bin/aws"],
        "process_names": ["TimeMachineHelper"],
        "ip_cidrs": ["10.0.0.0/8"],
    }))
    os.chmod(path, 0o600)
    os.chmod(tmp_path, 0o700)
    a = Allowlist.from_file(path)
    assert a.is_protected(exe_path="/usr/bin/aws") is True
    assert a.is_protected(proc_name="TimeMachineHelper") is True
    assert a.is_protected(ip="10.1.2.3") is True


@posix_only
def test_load_refuses_world_writable(tmp_path):
    path = tmp_path / "allowlist.json"
    path.write_text(json.dumps({"exe_paths": ["/usr/bin/aws"]}))
    os.chmod(path, 0o666)  # world-writable on purpose
    a = Allowlist.from_file(path)
    # Refusal returns an empty allowlist; nothing should match.
    assert a.is_protected(exe_path="/usr/bin/aws") is False


def test_missing_file_returns_empty(tmp_path):
    a = Allowlist.from_file(tmp_path / "does-not-exist.json")
    assert a.is_protected(exe_path="/anything") is False
