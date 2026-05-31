"""Windows interface enumeration (spec L1, v0.3).

The primary path (PowerShell ``Get-NetAdapter``) returns structured
JSON and is locale-independent. The legacy netsh path is kept as a
fallback. These tests stub ``subprocess.check_output`` to exercise
both paths without a real Windows host.
"""

from __future__ import annotations

import json

import zee.responder.cut_full as cf


def _stub_check_output(payload: str):
    def _stub(cmd, *, text=True, timeout=None):
        return payload
    return _stub


def test_powershell_path_parses_array(monkeypatch, tmp_path):
    payload = json.dumps([
        {"Name": "Ethernet", "Status": "Up"},
        {"Name": "Wi-Fi", "Status": "Disabled"},
        {"Name": "vEthernet (WSL)", "Status": "Up"},
    ])
    monkeypatch.setattr(cf.shutil, "which",
                        lambda name: "/usr/bin/powershell" if name == "powershell" else None)
    monkeypatch.setattr(cf.subprocess, "check_output", _stub_check_output(payload))
    enabled = cf.list_windows_interfaces(only_enabled=True)
    assert enabled == ["Ethernet", "vEthernet (WSL)"]
    all_ifs = cf.list_windows_interfaces(only_enabled=False)
    assert all_ifs == ["Ethernet", "Wi-Fi", "vEthernet (WSL)"]


def test_powershell_path_parses_single_object(monkeypatch):
    """PowerShell returns a bare object (not an array) when there is only one item."""
    payload = json.dumps({"Name": "Ethernet", "Status": "Up"})
    monkeypatch.setattr(cf.shutil, "which",
                        lambda name: "/usr/bin/powershell" if name == "powershell" else None)
    monkeypatch.setattr(cf.subprocess, "check_output", _stub_check_output(payload))
    assert cf.list_windows_interfaces(only_enabled=True) == ["Ethernet"]


def test_powershell_unavailable_falls_back_to_netsh(monkeypatch):
    """When PowerShell is missing, the netsh parser runs instead."""
    monkeypatch.setattr(cf.shutil, "which", lambda name: None)

    # Real netsh output has three header lines (title, ruler, blank).
    netsh_output = (
        "Admin State    State          Type             Interface Name\n"
        "-------------------------------------------------------------------------\n"
        "\n"
        "Enabled        Connected      Dedicated        Ethernet\n"
        "Disabled       Disconnected   Dedicated        Wi-Fi\n"
    )
    monkeypatch.setattr(cf.subprocess, "check_output",
                        _stub_check_output(netsh_output))
    enabled = cf.list_windows_interfaces(only_enabled=True)
    assert enabled == ["Ethernet"]
    all_ifs = cf.list_windows_interfaces(only_enabled=False)
    assert all_ifs == ["Ethernet", "Wi-Fi"]


def test_powershell_returns_status_up_only(monkeypatch):
    """``NotPresent`` and ``Disconnected`` adapters are treated as disabled,
    so only_enabled=True excludes them."""
    payload = json.dumps([
        {"Name": "Ethernet", "Status": "Up"},
        {"Name": "Bluetooth", "Status": "NotPresent"},
        {"Name": "Cellular", "Status": "Disconnected"},
    ])
    monkeypatch.setattr(cf.shutil, "which",
                        lambda name: "/usr/bin/powershell" if name == "powershell" else None)
    monkeypatch.setattr(cf.subprocess, "check_output", _stub_check_output(payload))
    assert cf.list_windows_interfaces(only_enabled=True) == ["Ethernet"]


def test_malformed_powershell_output_falls_back(monkeypatch):
    """If PowerShell returns non-JSON garbage, fall back to netsh."""
    monkeypatch.setattr(cf.shutil, "which",
                        lambda name: "/usr/bin/powershell" if name == "powershell" else None)

    call_count = {"n": 0}

    def _stub(cmd, *, text=True, timeout=None):
        call_count["n"] += 1
        if cmd[0] == "/usr/bin/powershell":
            return "not json at all"
        # netsh fallback path (real output has three header lines)
        return (
            "Admin State    State          Type             Interface Name\n"
            "-------------------------------------------------------------------------\n"
            "\n"
            "Enabled        Connected      Dedicated        Ethernet\n"
        )
    monkeypatch.setattr(cf.subprocess, "check_output", _stub)
    assert cf.list_windows_interfaces(only_enabled=True) == ["Ethernet"]
    assert call_count["n"] == 2  # PowerShell tried, netsh fallback
