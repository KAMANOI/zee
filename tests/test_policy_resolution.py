"""Asset profile → response mode resolution tests (spec §6)."""

from __future__ import annotations

from zee.config.schema import AssetProfile
from zee.policy.asset_profile import resolve


def _profile(**overrides) -> AssetProfile:
    base = dict(
        id="x", type="workstation", overnight_active=False,
        decoy_paths=("/tmp/x",),
        response_mode="notify", cut_method="full",
    )
    base.update(overrides)
    return AssetProfile(**base)  # type: ignore[arg-type]


def test_auto_resolves_to_contain():
    r = resolve(_profile(response_mode="auto", cut_method="egress"))
    assert r.mode == "contain"
    assert r.cut_method == "egress"


def test_staged_resolves_to_staged():
    r = resolve(_profile(response_mode="staged", cut_method="full"))
    assert r.mode == "staged"
    assert r.cut_method == "full"


def test_notify_resolves_to_notify_with_no_cut_method():
    r = resolve(_profile(response_mode="notify"))
    assert r.mode == "notify"
    assert r.cut_method is None
