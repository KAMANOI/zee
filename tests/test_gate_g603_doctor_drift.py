"""G603 (provider key passed whole to a container) and the doctor egress drift line."""
import io

import pytest

from zee import doctor
from zee.gate import static_checks


def _codes(tmp_path, files):
    for rel, body in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return {f.code for f in static_checks.scan_tree(tmp_path)}


@pytest.mark.parametrize("rel,body", [
    ("Dockerfile", "FROM x\nENV ANTHROPIC_API_KEY=sk-ant-dummy\n"),
    ("Dockerfile.dev", "FROM x\nARG OPENAI_API_KEY\n"),
    ("run.sh", "docker run --rm -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY img\n"),
    ("run.sh", "docker run -it \\\n  --env AWS_SECRET_ACCESS_KEY img\n"),
    ("compose.yaml", "services:\n  a:\n    environment:\n      ANTHROPIC_API_KEY: ${ANTHROPIC_API_KEY}\n"),
    ("compose.yml", "services:\n  a:\n    environment:\n      - ANTHROPIC_API_KEY\n"),
    ("compose.yml", "services:\n  a:\n    environment:\n      OPENAI_API_KEY:\n"),
    ("Dockerfile", "FROM x\nENV APP_MODE=prod OPENAI_API_KEY=$OPENAI_API_KEY\n"),
    ("run.sh", "docker run --pull=never -e OPENAI_API_KEY demo\n"),
    ("compose.yaml", "services:\n  a:\n    environment:\n    - OPENAI_API_KEY\n"),  # same-indent list
])
def test_g603_bad(tmp_path, rel, body):
    assert "G603" in _codes(tmp_path, {rel: body})


@pytest.mark.parametrize("rel,body", [
    ("Dockerfile", "FROM x\nENV APP_MODE=prod\n# ENV ANTHROPIC_API_KEY=x\n"),
    ("run.sh", "docker run --rm -e SESSION_TOKEN=$T img\n"),
    ("run.sh", "# never docker run -e ANTHROPIC_API_KEY\necho ok\n"),
    ("README.md", "docker run -e ANTHROPIC_API_KEY=... img\n"),
    ("tests/run.sh", "docker run -e ANTHROPIC_API_KEY img\n"),
    ("ci.yaml", "env:\n  ANTHROPIC_API_KEY: ${{ secrets.K }}\n"),  # not a compose file
    ("compose.yaml", "services:\n  a:\n    environment:\n      LOG: 1\n"),
    ("compose.yaml", "services:\n  a:\n    labels:\n      OPENAI_API_KEY: doc\n"),
    ("compose.yaml", "services:\n  a:\n    environment:\n      LOG: 1\n    labels:\n      OPENAI_API_KEY: x\n"),
    ("compose.yaml", "services:\n  a:\n    environment:\n    - LOG=1\n    labels:\n      OPENAI_API_KEY: x\n"),
])
def test_g603_clean(tmp_path, rel, body):
    assert "G603" not in _codes(tmp_path, {rel: body})


# ---- doctor: egress drift -------------------------------------------------

NFT = "__zee_nft_egress_table__"
IPT4, IPT6 = "__zee_iptables_egress_chain__", "__zee_ip6tables_egress_chain__"


def _doctor(tmp_path, monkeypatch, states, *, record=False, damaged=False, cuts=()):
    h = tmp_path / "h"
    h.mkdir()
    for k in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(k, str(h))
    monkeypatch.setenv("XDG_STATE_HOME", str(h / "state"))
    cfg = tmp_path / "assets.toml"
    cfg.write_text('dry_run = true\n[[assets]]\nid = "a"\ndecoy_paths = ["%s"]\n' % (h / "d.txt"))
    cfg.chmod(0o600)
    if damaged:
        from zee.telemetry.cut_state import default_cut_state_path
        default_cut_state_path().parent.mkdir(parents=True, exist_ok=True)
        default_cut_state_path().write_text("not json\n")
    if record:
        cuts = [("egress", [NFT]), *cuts]
    from zee.telemetry.cut_state import CutStateLog
    for method, modified in cuts:
        CutStateLog().record_cut(asset_id="a", method=method, platform="linux", modified=modified)
    buf = io.StringIO()
    doctor.run(cfg, ps=lambda: [], egress=lambda: states, out=buf)
    return buf.getvalue()


def _line(out):
    return next((ln for ln in out.splitlines() if "egress rules" in ln), "")


def test_doctor_absent_is_ok(tmp_path, monkeypatch):
    assert "[OK] egress rules" in _line(_doctor(tmp_path, monkeypatch, {"nft": "absent"}))


def test_doctor_unexpected_shape_warns(tmp_path, monkeypatch):
    assert "[WARN] egress rules" in _line(_doctor(tmp_path, monkeypatch, {"nft": "unexpected"}))


def test_doctor_rules_without_record_warns(tmp_path, monkeypatch):
    assert "[WARN] egress rules" in _line(_doctor(tmp_path, monkeypatch, {"nft": "present"}))


def test_doctor_unreadable_is_info(tmp_path, monkeypatch):
    assert "[INFO] egress rules" in _line(_doctor(tmp_path, monkeypatch, {"pf": "unreadable"}))


def test_doctor_other_platform_prints_nothing(tmp_path, monkeypatch):
    assert _line(_doctor(tmp_path, monkeypatch, {})) == ""


def test_doctor_rules_with_record_is_ok(tmp_path, monkeypatch):
    assert "[OK] egress rules" in _line(_doctor(tmp_path, monkeypatch, {"nft": "present"}, record=True))


def test_doctor_record_without_rules_warns(tmp_path, monkeypatch):
    assert "[WARN] egress rules" in _line(_doctor(tmp_path, monkeypatch, {"nft": "absent"}, record=True))


def test_doctor_damaged_record_is_not_compared(tmp_path, monkeypatch):
    out = _doctor(tmp_path, monkeypatch, {"nft": "absent"}, damaged=True)
    assert "[INFO] egress rules" in _line(out)


@pytest.mark.parametrize("plat,tool,table,expect", [
    ("linux", "nft", "table inet zee_egress {\n chain o {\n type filter hook output priority 0; policy drop;\n accept\n }\n}", "unexpected"),
    ("linux", "nft", "table inet zee_egress {\n chain o {\n type filter hook output priority 0; policy drop;\n }\n}", "present"),
])
def test_egress_state_reads_with_shape(monkeypatch, plat, tool, table, expect):
    monkeypatch.setattr(doctor.sys, "platform", plat)
    monkeypatch.setattr(doctor, "sbin_which", lambda n: "/x/" + n if n == "nft" else None)
    monkeypatch.setattr(doctor, "_run", lambda cmd: (True, table))
    st = doctor._egress_state()
    assert st["nft"] == expect and st["iptables"] == "unreadable"  # missing tool is reported, not dropped


# ---- review round 2 ---------------------------------------------------------

def test_doctor_ipv6_chain_deleted_warns(tmp_path, monkeypatch):
    # IPv4 chain still there, IPv6 chain gone: not "no drift"
    out = _doctor(tmp_path, monkeypatch, {"nft": "unreadable", "iptables": "present", "ip6tables": "absent"},
                  cuts=[("egress", [IPT4, IPT6, "__zee_iptables_backend__:nf_tables"])])
    assert "[WARN] egress rules" in _line(out) and "ip6tables" in _line(out)


def test_egress_state_reads_ip6tables_of_same_backend(monkeypatch):
    monkeypatch.setattr(doctor.sys, "platform", "linux")
    monkeypatch.setattr(doctor, "sbin_which", lambda n: "/x/" + n if n.startswith("ip") else None)
    monkeypatch.setattr(doctor, "kernel_ipv6_absent", lambda: False)
    seen = []
    monkeypatch.setattr(doctor, "_ip6tables_tool", lambda b: seen.append(b) or "ip6tables-legacy")
    chain = "-N ZEE_EGRESS\n-A ZEE_EGRESS -j DROP"
    monkeypatch.setattr(doctor, "_run", lambda cmd: (True, "iptables v1.8.7 (legacy)") if cmd[-1] == "--version"
                        else (True, "") if cmd[0].endswith("ip6tables-legacy") else (True, chain))
    st = doctor._egress_state()
    assert seen == ["legacy"] and st["iptables"] == "present" and st["ip6tables"] == "absent"


def test_egress_state_nft_counter_accept_is_unexpected(monkeypatch):
    table = ("table inet zee_egress {\n chain o {\n type filter hook output priority 0; policy drop;\n"
             " counter packets 0 bytes 0 accept\n }\n}")
    monkeypatch.setattr(doctor.sys, "platform", "linux")
    monkeypatch.setattr(doctor, "sbin_which", lambda n: "/x/" + n if n == "nft" else None)
    monkeypatch.setattr(doctor, "_run", lambda cmd: (True, table))
    assert doctor._egress_state()["nft"] == "unexpected"


def test_doctor_egress_then_full_still_compares_firewall(tmp_path, monkeypatch):
    # latest cut is full, but the egress table from the first cut is still in the record
    out = _doctor(tmp_path, monkeypatch, {"nft": "absent"}, cuts=[("egress", [NFT]), ("full", ["eth0"])])
    assert "[WARN] egress rules" in _line(out)
    (tmp_path / "b").mkdir()
    out2 = _doctor(tmp_path / "b", monkeypatch, {"nft": "present"}, cuts=[("egress", [NFT]), ("full", ["eth0"])])
    assert "[OK] egress rules" in _line(out2)
