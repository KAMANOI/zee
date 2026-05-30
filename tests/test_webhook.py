"""Webhook sender — best-effort, never raises (spec §5)."""

from __future__ import annotations

import json

import pytest

from zee.notifier import webhook


class _StubResponse:
    def __init__(self, status: int) -> None:
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def getcode(self):
        return self.status


def test_post_success(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["body"] = req.data
        return _StubResponse(200)

    monkeypatch.setattr(webhook.urllib.request, "urlopen", fake_urlopen)
    ok, detail = webhook.post("https://hook.example.com/x", {"k": "v"})
    assert ok is True
    assert detail.startswith("HTTP")
    assert captured["url"] == "https://hook.example.com/x"
    assert json.loads(captured["body"]) == {"k": "v"}


def test_post_http_error(monkeypatch):
    monkeypatch.setattr(
        webhook.urllib.request, "urlopen",
        lambda req, timeout=None: _StubResponse(503),
    )
    ok, detail = webhook.post("https://hook.example.com/x", {})
    assert ok is False
    assert "503" in detail


def test_post_network_error_never_raises(monkeypatch):
    def boom(req, timeout=None):
        raise OSError("connection refused")

    monkeypatch.setattr(webhook.urllib.request, "urlopen", boom)
    ok, detail = webhook.post("https://hook.example.com/x", {})
    assert ok is False
    assert "connection refused" in detail


def test_from_env_returns_none_when_unset(monkeypatch):
    monkeypatch.delenv("ZEE_WEBHOOK_URL", raising=False)
    assert webhook.from_env() is None


def test_from_env_returns_sender_when_set(monkeypatch):
    monkeypatch.setenv("ZEE_WEBHOOK_URL", "https://hook.example.com/x")
    sender = webhook.from_env()
    assert sender is not None
    monkeypatch.setattr(
        webhook.urllib.request, "urlopen",
        lambda req, timeout=None: _StubResponse(200),
    )
    ok, _ = sender("test title", {"asset_id": "h", "detail": "d"})
    assert ok is True
