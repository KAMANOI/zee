"""G603 (provider key passed whole to a container) and the doctor egress drift line."""
import io
import json

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

_OIF_LO = {"match": {"op": "==", "left": {"meta": {"key": "oif"}}, "right": "lo"}}


def _nftj(rules, *, hook="output", policy="drop"):
    """A faked `nft -j list table inet zee_egress` dump. `rules` is a list of
    rule dicts (each with its own `expr`, optional `comment`)."""
    objs = [{"metainfo": {"version": "1.0"}},
            {"table": {"family": "inet", "name": "zee_egress"}},
            {"chain": {"family": "inet", "table": "zee_egress", "name": "out",
                       "type": "filter", "hook": hook, "prio": 0, "policy": policy}}]
    for r in rules:
        objs.append({"rule": {"family": "inet", "table": "zee_egress", "chain": "out", **r}})
    return json.dumps({"nftables": objs})


def _doctor(tmp_path, monkeypatch, states, *, record=False, damaged=False, cuts=()):
    h = tmp_path / "h"
    h.mkdir()
    for k in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(k, str(h))
    monkeypatch.setenv("XDG_STATE_HOME", str(h / "state"))
    cfg = tmp_path / "assets.toml"
    # .as_posix(): a Windows decoy path (C:\...) inside a double-quoted TOML
    # string hits \-escape parsing (\U, \A, ...) and the config fails to load,
    # which would make this helper's config unusable only on Windows.
    cfg.write_text('dry_run = true\n[[assets]]\nid = "a"\ndecoy_paths = ["%s"]\n' % (h / "d.txt").as_posix())
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


@pytest.mark.parametrize("table,expect", [
    # a bare unconditional accept (no match) is a bypass -> unexpected
    (_nftj([{"expr": [_OIF_LO, {"accept": None}]}, {"expr": [{"accept": None}]}]), "unexpected"),
    # only conditional accepts + the drop policy -> the shape Zee loads
    (_nftj([{"expr": [_OIF_LO, {"accept": None}]}]), "present"),
])
def test_egress_state_reads_with_shape(monkeypatch, table, expect):
    monkeypatch.setattr(doctor.sys, "platform", "linux")
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
    output = "-P OUTPUT ACCEPT\n-A OUTPUT -j ZEE_EGRESS"  # OUTPUT jump read back (round 3)
    monkeypatch.setattr(doctor, "_run", lambda cmd: (True, "iptables v1.8.7 (legacy)") if cmd[-1] == "--version"
                        else (True, "") if cmd[0].endswith("ip6tables-legacy")
                        else (True, output) if cmd[-1] == "OUTPUT" else (True, chain))
    st = doctor._egress_state()
    assert seen == ["legacy"] and st["iptables"] == "present" and st["ip6tables"] == "absent"


def test_egress_state_nft_json_counter_and_hash_comment(monkeypatch):
    # finding #2: decide via `nft -j` JSON structurally, not text munging. A
    # clean cut reads as present; an unconditional accept carrying a counter and
    # a rule comment with '#' in it is a bypass -> unexpected. (The old text
    # parser split on '#', mangled the comment, and read the accept as present.)
    monkeypatch.setattr(doctor.sys, "platform", "linux")
    monkeypatch.setattr(doctor, "sbin_which", lambda n: "/x/" + n if n == "nft" else None)

    def nft(table):
        monkeypatch.setattr(doctor, "_run", lambda cmd: (True, table))
        return doctor._egress_state()["nft"]

    clean = _nftj([{"expr": [_OIF_LO, {"accept": None}]}])
    bypass = _nftj([{"comment": 'ticket #123',
                     "expr": [{"counter": {"packets": 0, "bytes": 0}}, {"accept": None}]}])
    assert nft(clean) == "present"
    assert nft(bypass) == "unexpected"


def test_egress_state_nft_non_json_is_unreadable(monkeypatch):
    # an old nft without `-j` prints text, not JSON: unchecked, never present.
    monkeypatch.setattr(doctor.sys, "platform", "linux")
    monkeypatch.setattr(doctor, "sbin_which", lambda n: "/x/" + n if n == "nft" else None)
    monkeypatch.setattr(doctor, "_run", lambda cmd: (True, "table inet zee_egress { chain o { } }"))
    assert doctor._egress_state()["nft"] == "unreadable"


# ---- review round 3 ---------------------------------------------------------

def test_egress_state_iptables_without_output_jump_is_unexpected(monkeypatch):
    # chain + DROP are still there, but OUTPUT no longer jumps to ZEE_EGRESS:
    # the block is disabled and must not read as "present".
    chain = "-N ZEE_EGRESS\n-A ZEE_EGRESS -j DROP"
    output = "-P OUTPUT ACCEPT"  # jump to ZEE_EGRESS removed
    monkeypatch.setattr(doctor.sys, "platform", "linux")
    monkeypatch.setattr(doctor, "sbin_which", lambda n: "/x/" + n if n == "iptables" else None)
    monkeypatch.setattr(doctor, "kernel_ipv6_absent", lambda: True)  # skip the v6 branch
    monkeypatch.setattr(doctor, "_run", lambda cmd: (True, output) if cmd[-1] == "OUTPUT"
                        else (True, chain))
    assert doctor._egress_state()["iptables"] == "unexpected"


def test_egress_state_pf_block_rule_is_unverified_not_present(monkeypatch):
    # finding #1: on macOS the single pf read shows the block rule, but cannot
    # confirm pf is enabled and its anchor referenced -> report "unverified",
    # never "present".
    rules = ("pass out quick on lo0 all\npass out quick to 10.0.0.0/8\n"
             "pass out quick to 172.16.0.0/12\npass out quick to 192.168.0.0/16\n"
             "block drop out quick all\n")
    monkeypatch.setattr(doctor.sys, "platform", "darwin")
    monkeypatch.setattr(doctor, "sbin_which", lambda n: "/x/" + n if n == "pfctl" else None)
    monkeypatch.setattr(doctor, "_run", lambda cmd: (True, rules))
    assert doctor._egress_state()["pf"] == "unverified"


def test_doctor_pf_unverified_warns_not_ok(tmp_path, monkeypatch):
    out = _line(_doctor(tmp_path, monkeypatch, {"pf": "unverified"}))
    assert "[WARN] egress rules" in out and "[OK]" not in out


def test_g603_compose_comment_does_not_close_env_block(tmp_path):
    # a comment at the key's own indent must not end the environment block
    body = "services:\n  a:\n    environment:\n    # a comment\n    - OPENAI_API_KEY\n"
    assert "G603" in _codes(tmp_path, {"compose.yaml": body})


def test_g603_env_block_with_eol_comment(tmp_path):
    # finding #3: an end-of-line comment on the `environment:` line must not hide
    # the block, or the key under it misses G603.
    body = "services:\n  a:\n    environment: # credentials\n      - OPENAI_API_KEY\n"
    assert "G603" in _codes(tmp_path, {"compose.yaml": body})


def test_doctor_egress_then_full_still_compares_firewall(tmp_path, monkeypatch):
    # latest cut is full, but the egress table from the first cut is still in the record
    out = _doctor(tmp_path, monkeypatch, {"nft": "absent"}, cuts=[("egress", [NFT]), ("full", ["eth0"])])
    assert "[WARN] egress rules" in _line(out)
    (tmp_path / "b").mkdir()
    out2 = _doctor(tmp_path / "b", monkeypatch, {"nft": "present"}, cuts=[("egress", [NFT]), ("full", ["eth0"])])
    assert "[OK] egress rules" in _line(out2)


# ---- convergent allowlist redesign: each prior whack-a-mole bypass ----------
# The drift check now judges the chain by an allowlist of the exact rule shapes
# `cut_egress._cut_egress_linux` loads; anything else is drift (fail closed).

_V4_FULL = ("-N ZEE_EGRESS\n-A ZEE_EGRESS -o lo -j ACCEPT\n"
            "-A ZEE_EGRESS -d 10.0.0.0/8 -j ACCEPT\n"
            "-A ZEE_EGRESS -d 172.16.0.0/12 -j ACCEPT\n"
            "-A ZEE_EGRESS -d 192.168.0.0/16 -j ACCEPT\n-A ZEE_EGRESS -j DROP")
_OUTPUT_JUMP = "-P OUTPUT ACCEPT\n-A OUTPUT -j ZEE_EGRESS"


def _ipt_state(monkeypatch, chain, output=_OUTPUT_JUMP):
    monkeypatch.setattr(doctor.sys, "platform", "linux")
    monkeypatch.setattr(doctor, "sbin_which", lambda n: "/x/" + n if n == "iptables" else None)
    monkeypatch.setattr(doctor, "kernel_ipv6_absent", lambda: True)  # skip the v6 branch
    monkeypatch.setattr(doctor, "_run", lambda cmd: (True, output) if cmd[-1] == "OUTPUT" else (True, chain))
    return doctor._egress_state()["iptables"]


def _nft_state(monkeypatch, table):
    monkeypatch.setattr(doctor.sys, "platform", "linux")
    monkeypatch.setattr(doctor, "sbin_which", lambda n: "/x/" + n if n == "nft" else None)
    monkeypatch.setattr(doctor, "_run", lambda cmd: (True, table))
    return doctor._egress_state()["nft"]


def _daddr(net):
    a, length = net.split("/")
    return {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}},
                      "right": {"prefix": {"addr": a, "len": int(length)}}}}


def test_iptables_return_before_drop_is_not_present(monkeypatch):
    # bypass (round 3): a RETURN ahead of the DROP escapes the chain to OUTPUT.
    chain = ("-N ZEE_EGRESS\n-A ZEE_EGRESS -o lo -j ACCEPT\n"
             "-A ZEE_EGRESS -j RETURN\n-A ZEE_EGRESS -j DROP")
    assert _ipt_state(monkeypatch, chain) == "unexpected"


def test_iptables_accept_to_other_host_is_not_present(monkeypatch):
    # bypass: a narrow ACCEPT to a non-local host (has a -d, so not "unconditional").
    chain = _V4_FULL.replace("-A ZEE_EGRESS -j DROP",
                             "-A ZEE_EGRESS -d 203.0.113.5/32 -j ACCEPT\n-A ZEE_EGRESS -j DROP")
    assert _ipt_state(monkeypatch, chain) == "unexpected"


def test_iptables_full_chain_is_present(monkeypatch):  # positive control
    assert _ipt_state(monkeypatch, _V4_FULL) == "present"


@pytest.mark.parametrize("verdict", [{"jump": {"target": "sneaky"}}, {"goto": {"target": "sneaky"}}])
def test_nft_jump_or_goto_out_of_drop_chain_is_not_present(monkeypatch, verdict):
    # bypass: a jump/goto to another chain that accepts -- no `accept` verdict in
    # the drop chain's own rule, so the denylist check read it as present.
    table = _nftj([{"expr": [_OIF_LO, {"accept": None}]}, {"expr": [verdict]}])
    assert _nft_state(monkeypatch, table) == "unexpected"


def test_nft_accept_to_other_host_is_not_present(monkeypatch):
    # bypass: a conditional accept to a destination Zee never loads (match+accept,
    # so a statement-type view would miss it; the value allowlist catches it).
    table = _nftj([{"expr": [_OIF_LO, {"accept": None}]}, {"expr": [_daddr("203.0.113.5/32"), {"accept": None}]}])
    assert _nft_state(monkeypatch, table) == "unexpected"


def test_nft_full_local_table_is_present(monkeypatch):  # positive control
    rules = [{"expr": [_OIF_LO, {"accept": None}]}]
    rules += [{"expr": [_daddr(n), {"accept": None}]}
              for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
    assert _nft_state(monkeypatch, _nftj(rules)) == "present"
