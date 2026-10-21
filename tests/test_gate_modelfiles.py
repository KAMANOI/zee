"""G221-G229: AI model files, judged by their first bytes, never loaded.

Pickles are built with pickle.dumps (which does not run the payload); the
payload of the executing-check test would touch a marker file if anything
ever loaded it.
"""

from __future__ import annotations

import json
import os
import pickle
import struct
import zipfile
from collections import OrderedDict
from pathlib import Path

from zee.gate import static_checks
from zee.gate.inspector import inspect_source, promote_if_low
from zee.gate.model import InspectionStatus


class _Evil:
    marker = ""

    def __reduce__(self):
        return (os.system, (f"touch {self.marker}",))


def _evil(marker="/nonexistent/x", proto=4) -> bytes:
    _Evil.marker = marker
    return pickle.dumps(_Evil(), protocol=proto)


def _scan(tmp: Path, files: dict[str, bytes | str]):
    for rel, body in files.items():
        p = tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(body if isinstance(body, bytes) else body.encode())
    return static_checks.scan_tree(tmp)


def _codes(flags) -> dict[str, list]:
    out: dict[str, list] = {}
    for f in flags:
        out.setdefault(f.code, []).append(f)
    return out


def _st(tensors: dict, meta=None, extra=0) -> bytes:
    hdr, data, pos = {}, b"", 0
    for k, (dt, shape, n) in tensors.items():
        hdr[k] = {"dtype": dt, "shape": shape, "data_offsets": [pos, pos + n]}
        pos += n
        data += b"\0" * n
    if meta is not None:
        hdr["__metadata__"] = meta
    h = json.dumps(hdr).encode()
    return struct.pack("<Q", len(h)) + h + data + b"\0" * extra


def _gguf(template: str | None) -> bytes:
    def s(x: str) -> bytes:
        b = x.encode()
        return struct.pack("<Q", len(b)) + b

    kv = s("general.name") + struct.pack("<I", 8) + s("m")
    n = 1
    if template is not None:
        kv += s("tokenizer.chat_template") + struct.pack("<I", 8) + s(template)
        n = 2
    return b"GGUF" + struct.pack("<IQQ", 3, 0, n) + kv


# --- pickle ------------------------------------------------------------------
def test_dangerous_pickle_is_high_and_not_run(tmp_path):
    marker = tmp_path / "ran"
    c = _codes(_scan(tmp_path / "m", {"pytorch_model.bin": _evil(str(marker))}))
    assert c["G222"][0].severity.value == "high" and "system" in c["G222"][0].evidence
    assert c["G221"][0].severity.value == "medium"
    assert not marker.exists()


def test_dangerous_pickle_protocol0_and_2(tmp_path):
    for i, proto in enumerate((0, 2)):
        c = _codes(_scan(tmp_path / str(i), {"w.pkl": _evil(proto=proto)}))
        assert "G222" in c, proto


def test_memoized_string_import_is_resolved(tmp_path):
    # protocol 4: strings pushed, memoized, fetched again with BINGET, then STACK_GLOBAL
    body = (b"\x80\x04\x8c\x05posix\x94\x8c\x06system\x94"  # both strings memoized, then dropped
            b"00h\x00h\x01\x93\x8c\x04echo\x85R.")  # fetched with BINGET, STACK_GLOBAL, REDUCE
    assert "G222" in _codes(_scan(tmp_path, {"w.pkl": body}))


def test_plain_pickle_is_medium_only_and_blocks_promote(tmp_path):
    src = tmp_path / "m"
    _scan(src, {"pytorch_model.bin": pickle.dumps(OrderedDict(a=1), protocol=2),
                "w2.pkl": pickle.dumps({"a": 1})})
    v = inspect_source(src, quarantine_base=tmp_path / "q")
    c = _codes(v.flags)
    assert len(c["G221"]) == 1  # once per tree, however many files
    assert "G222" not in c and "G223" not in c
    assert v.risk_level.value == "MEDIUM" and v.inspection is InspectionStatus.COMPLETE
    ok, msg = promote_if_low(v, tmp_path / "dest")
    assert not ok and "MEDIUM" in msg


def test_unknown_import_is_medium(tmp_path):
    c = _codes(_scan(tmp_path, {"w.pkl": pickle.dumps(Path("x"), protocol=4)}))
    assert c["G223"][0].severity.value == "medium"


def test_truncated_dangerous_pickle_is_high(tmp_path):
    c = _codes(_scan(tmp_path, {"w.bin": _evil()[:-3]}))
    assert c["G224"][0].severity.value == "high" and "G222" in c
    assert "G225" in c  # HIGH found, but the file was not read to its end: inspection is partial too


def test_truncated_plain_pickle_is_a_gap(tmp_path):
    v = inspect_source(_mk(tmp_path / "m", {"w.pt": pickle.dumps(["a" * 50], protocol=4)[:-4]}),
                       quarantine_base=tmp_path / "q")
    assert "G225" in _codes(v.flags)
    assert v.inspection is InspectionStatus.PARTIAL and v.exit_code == 3


def _mk(d: Path, files):
    _scan(d, files)
    return d


def test_zip_pickle_checked_in_memory(tmp_path):
    for name, body, want in (("bad.pt", _evil(), True), ("ok.pt", pickle.dumps(OrderedDict(a=1)), False)):
        p = tmp_path / name
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("archive/data.pkl", body)
            z.writestr("archive/data/0", b"\0" * 8)
        c = _codes(static_checks.scan_tree(_only(tmp_path, p)))
        assert ("G222" in c) is want and "G221" in c


def _only(tmp: Path, p: Path) -> Path:
    d = tmp / (p.stem + "_d")
    d.mkdir()
    p.rename(d / p.name)
    return d


def test_encrypted_or_broken_zip_is_a_gap(tmp_path):
    c = _codes(_scan(tmp_path, {"w.pth": b"PK\x03\x04" + b"\0" * 40}))
    assert "G225" in c


def test_huge_pickle_claim_is_capped_not_allocated(tmp_path):
    # BINBYTES8 claiming 1 TiB: must stop at the cap, not allocate
    body = b"\x80\x04\x8e" + struct.pack("<Q", 1 << 40) + b"x"
    c = _codes(_scan(tmp_path, {"w.pkl": body}))
    assert "G225" in c


def test_legacy_multi_stream_pickle_with_trailing_raw_data(tmp_path):
    body = pickle.dumps(1, protocol=2) + pickle.dumps(OrderedDict(a=1), protocol=2) + b"\xff" * 64
    c = _codes(_scan(tmp_path, {"w.pth": body}))
    assert "G225" not in c and "G224" not in c and "G221" in c
    # legacy raw region starts with an int64 count: 128 reads as PROTO, then dies; still not a cut-off stream
    body = pickle.dumps(1, protocol=2) + pickle.dumps(OrderedDict(a=1), protocol=2) + struct.pack("<q", 128) + b"\0" * 64
    c = _codes(_scan(tmp_path / "b", {"w.pth": body}))
    assert "G225" not in c and "G224" not in c and "G221" in c


# --- safetensors -------------------------------------------------------------
def test_valid_safetensors_is_clean(tmp_path):
    src = _mk(tmp_path / "m", {"model.safetensors": _st({"a": ("F32", [2, 2], 16), "b": ("U8", [3], 3)}, {"format": "pt"})})
    v = inspect_source(src, quarantine_base=tmp_path / "q")
    assert v.risk_level.value == "LOW" and not v.flags and v.inspection is InspectionStatus.COMPLETE


def test_bad_safetensors_variants_are_high(tmp_path):
    good = _st({"a": ("F32", [2, 2], 16)})
    n = struct.unpack("<Q", good[:8])[0]
    hdr = good[8:8 + n]
    variants = {
        "size": _st({"a": ("F32", [2, 3], 16)}),
        "meta": _st({"a": ("U8", [1], 1)}, {"k": 1}),
        "tail": _st({"a": ("U8", [1], 1)}, extra=5),
        "dup": struct.pack("<Q", len(hdr) * 2 + 1) + hdr[:-1] + b"," + hdr[1:] + b"\0" * 16,
        "short": good[:-4],
        "notjson": struct.pack("<Q", 4) + b"{abc" + b"\0" * 4,
    }
    for k, body in variants.items():
        c = _codes(_scan(tmp_path / k, {"m.safetensors": body}))
        assert c["G226"][0].severity.value == "high", k


def test_hole_between_tensors_is_high(tmp_path):
    hdr = json.dumps({"a": {"dtype": "U8", "shape": [2], "data_offsets": [0, 2]},
                      "b": {"dtype": "U8", "shape": [2], "data_offsets": [3, 5]}}).encode()
    body = struct.pack("<Q", len(hdr)) + hdr + b"\0" * 5
    assert "G226" in _codes(_scan(tmp_path, {"m.safetensors": body}))


def test_pickle_under_safetensors_name_is_high(tmp_path):
    c = _codes(_scan(tmp_path, {"model.safetensors": _evil()}))
    assert c["G226"][0].severity.value == "high"


def test_multi_gb_files_are_not_read_whole(tmp_path):
    big = tmp_path / "m" / "big.safetensors"
    big.parent.mkdir()
    n = 3 * 1024**3
    hdr = json.dumps({"a": {"dtype": "U8", "shape": [n], "data_offsets": [0, n]}}).encode()
    with big.open("wb") as f:
        f.write(struct.pack("<Q", len(hdr)) + hdr)
        f.truncate(8 + len(hdr) + n)  # sparse
    assert static_checks.scan_tree(tmp_path / "m") == []


# --- GGUF / Keras ------------------------------------------------------------
def test_gguf_template_shown_low_and_attack_template_high(tmp_path):
    ok = _codes(_scan(tmp_path / "a", {"m.gguf": _gguf("{{ messages[0]['content'] }}")}))
    assert ok["G229"][0].severity.value == "low"
    bad = _codes(_scan(tmp_path / "b", {"m.gguf": _gguf("{{ ''.__class__.__mro__[1].__subclasses__() }}")}))
    assert bad["G229"][0].severity.value == "high"
    none = _scan(tmp_path / "c", {"m.gguf": _gguf(None)})
    assert not [f for f in none if f.code.startswith("G2")]


def test_gguf_name_with_other_content_is_high(tmp_path):
    assert "G226" in _codes(_scan(tmp_path, {"m.gguf": _evil()}))


def test_keras_h5_and_lambda(tmp_path):
    assert _codes(_scan(tmp_path / "a", {"m.h5": b"\x89HDF\r\n\x1a\n" + b"\0" * 20}))["G229"][0].severity.value == "medium"
    p = tmp_path / "b"
    p.mkdir()
    with zipfile.ZipFile(p / "m.keras", "w") as z:
        z.writestr("metadata.json", "{}")
        z.writestr("config.json", '{"layers": [{"class_name": "Lambda"}]}')
    assert "G229" in _codes(static_checks.scan_tree(p))


# --- companion code ----------------------------------------------------------
_CFG = json.dumps({"auto_map": {"AutoModel": "modeling_x.X"}, "trust_remote_code": False})


def test_auto_map_and_import_time_call(tmp_path):
    c = _codes(_scan(tmp_path, {
        "config.json": _CFG,
        "model.safetensors": _st({"a": ("U8", [1], 1)}),
        "modeling_x.py": "import os\nos.system('id')\nclass X: pass\n",
    }))
    assert {f.code for f in c["G227"]} == {"G227"} and len(c["G227"]) == 2  # config + modeling file
    assert c["G228"][0].severity.value == "high"


def test_default_arg_decorator_and_class_body_calls_count(tmp_path):
    for i, body in enumerate((
        "import os\ndef f(x=os.system('id')): pass\n",
        "import subprocess\n@subprocess.run('id')\ndef f(): pass\n",
        "import socket\nclass A:\n    s = socket.create_connection(('h', 1))\n",
        "exec('1')\n",
    )):
        c = _codes(_scan(tmp_path / str(i), {"model.safetensors": _st({"a": ("U8", [1], 1)}), "modeling_x.py": body}))
        assert c.get("G228") and c["G228"][0].severity.value == "high", body


def test_call_inside_function_body_is_not_import_time(tmp_path):
    c = _codes(_scan(tmp_path, {"model.safetensors": _st({"a": ("U8", [1], 1)}),
                                "modeling_x.py": "import os\ndef f():\n    os.system('id')\n"}))
    assert "G228" not in c and "G227" in c


def test_env_read_at_import_is_medium(tmp_path):
    c = _codes(_scan(tmp_path, {"model.safetensors": _st({"a": ("U8", [1], 1)}),
                                "configuration_x.py": "import os\nK = os.environ['AWS_KEY']\n"}))
    assert c["G228"][0].severity.value == "medium"


def test_trust_remote_code_true_only(tmp_path):
    base = {"model.safetensors": _st({"a": ("U8", [1], 1)})}
    yes = _codes(_scan(tmp_path / "y", {**base, "README.md": "AutoModel.from_pretrained(x, trust_remote_code=True)"}))
    no = _codes(_scan(tmp_path / "n", {**base, "README.md": "AutoModel.from_pretrained(x, trust_remote_code=False)"}))
    assert "G227" in yes and "G227" not in no


def test_companion_name_without_model_is_not_flagged(tmp_path):
    assert not [f for f in _scan(tmp_path, {"modeling_x.py": "x = 1\n"}) if f.code == "G227"]


def test_syntax_error_companion_is_a_gap(tmp_path):
    c = _codes(_scan(tmp_path, {"model.safetensors": _st({"a": ("U8", [1], 1)}), "modeling_x.py": "def (:\n"}))
    assert "G225" in c


def test_hash_of_a_file_is_chunked_and_stable(tmp_path):
    from zee.gate.fetch import sha256_tree
    import hashlib
    p = tmp_path / "f"
    p.write_bytes(b"abc" * 1_000_000)
    assert sha256_tree(p) == hashlib.sha256(b"abc" * 1_000_000).hexdigest()


def test_pickle_in_a_zip_under_any_name_is_read(tmp_path):
    p = tmp_path / "d" / "w.pt"
    p.parent.mkdir()
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("archive/payload.bin", _evil())
        z.writestr("archive/data/0", b"\x80\x03" + b"\xff" * 30)  # raw tensor slot that starts like a pickle but is not one
        z.writestr("archive/inner.zip", b"PK\x03\x04" + b"\0" * 30)
    c = _codes(static_checks.scan_tree(p.parent))
    assert len(c["G222"]) == 1 and "payload.bin" in c["G222"][0].evidence  # garbage slot is read but not misread as a pickle
    assert any("zip inside a zip" in f.message for f in c["G225"])


def test_whole_gate_exit_code_for_dangerous_pickle(tmp_path):
    v = inspect_source(_mk(tmp_path / "m", {"pytorch_model.bin": _evil()}), quarantine_base=tmp_path / "q")
    assert v.risk_level.value == "HIGH" and v.exit_code == 2


def test_oversize_manifest_is_unreadable_not_slurped(tmp_path):
    from zee.gate.adapters import manifest_flags
    d = tmp_path / "m"
    d.mkdir()
    with (d / "package.json").open("wb") as f:
        f.truncate(9 * 1024 * 1024)
    assert [f.code for f in manifest_flags(d)] == ["G912"]


def _p4(*parts: bytes) -> bytes:
    return b"\x80\x04" + b"".join(parts) + b"."


def _s(x: str) -> bytes:
    return b"\x8c" + bytes([len(x)]) + x.encode()


def test_dotted_attribute_path_is_high(tmp_path):
    body = _p4(_s("torch"), _s("os.system"), b"\x93", _s("echo"), b"\x85R")
    assert "G222" in _codes(_scan(tmp_path, {"w.pkl": body}))


def test_pop_between_strings_is_unresolved_not_misread(tmp_path):
    # real stack: posix, echo -> posix.echo; a push log would read system.echo and miss posix
    body = _p4(_s("posix"), _s("system"), b"0", _s("echo"), b"\x93")
    c = _codes(_scan(tmp_path, {"w.pkl": body}))
    assert "G225" in c and "G221" in c


def test_auto_map_target_with_any_name_is_checked(tmp_path):
    cfg = json.dumps({"auto_map": {"AutoModel": "myrepo--impl.Net"}})
    c = _codes(_scan(tmp_path, {"config.json": cfg, "impl.py": "import os\nos.system('id')\n"}))
    assert c["G228"][0].severity.value == "high" and len(c["G227"]) == 2


def test_aliased_imports_are_resolved(tmp_path):
    for i, body in enumerate(("import os as o\no.system('id')\n", "from os import system as s\ns('id')\n",
                              "from subprocess import run\nrun(['id'])\n")):
        c = _codes(_scan(tmp_path / str(i), {"model.safetensors": _st({"a": ("U8", [1], 1)}), "modeling_x.py": body}))
        assert c.get("G228"), body


def test_safetensors_head_under_a_pickle_name_is_high(tmp_path):
    c = _codes(_scan(tmp_path, {"pytorch_model.bin": _st({"a": ("U8", [1], 1)}), "m.pt": _st({"a": ("U8", [1], 1)})}))
    assert len(c["G226"]) == 2


def test_keras_custom_module_prefix_is_not_allowlisted(tmp_path):
    p = tmp_path / "b"
    p.mkdir()
    with zipfile.ZipFile(p / "m.keras", "w") as z:
        z.writestr("metadata.json", "{}")
        z.writestr("config.json", '{"module": "keras_evil.x"}')
    assert "G229" in _codes(static_checks.scan_tree(p))


# --- review fixes (2026-10-21) -------------------------------------------------
def test_pickle_zip_under_any_suffix_is_read(tmp_path):
    p = tmp_path / "d" / "weights.dat"
    p.parent.mkdir()
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("archive/data.pkl", _evil())
    c = _codes(static_checks.scan_tree(p.parent))
    assert "G222" in c and "G221" in c


def test_ordinary_zip_without_pickle_is_not_a_gap(tmp_path):
    p = tmp_path / "d" / "report.docx"
    p.parent.mkdir()
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("word/embeddings/sheet.xlsx", b"PK\x03\x04" + b"\0" * 30)
    assert static_checks.scan_tree(p.parent) == []


def test_keras_config_crc_mismatch_is_a_gap_not_a_crash(tmp_path):
    p = tmp_path / "d" / "m.keras"
    p.parent.mkdir()
    cfg = b'{"layers": [{"class_name": "Dense"}]}'
    with zipfile.ZipFile(p, "w", zipfile.ZIP_STORED) as z:
        z.writestr("metadata.json", "{}")
        z.writestr("config.json", cfg)
    p.write_bytes(p.read_bytes().replace(b"Dense", b"Dxnse"))
    assert "G225" in _codes(static_checks.scan_tree(p.parent))


def test_deeply_chained_companion_py_is_a_gap_not_a_crash(tmp_path):
    src = "import os\nos.system('id')\nx = " + "+".join(["1"] * 3000) + "\n"
    c = _codes(_scan(tmp_path, {"model.safetensors": _st({"a": ("U8", [1], 1)}), "modeling_x.py": src}))
    assert "G225" in c and "G228" in c


def test_second_stream_cut_after_import_is_broken(tmp_path):
    body = pickle.dumps(1, protocol=2) + _p4(_s("posix"), _s("system"), b"\x93")[:-1]  # no STOP
    c = _codes(_scan(tmp_path, {"w.pth": body}))
    assert "G222" in c and "G224" in c and "G225" in c


def test_gguf_unknown_version_is_a_gap_and_missing_tensors_are_high(tmp_path):
    assert "G225" in _codes(_scan(tmp_path / "a", {"m.gguf": b"GGUF" + struct.pack("<IQQ", 999, 0, 0)}))
    assert "G226" in _codes(_scan(tmp_path / "b", {"m.gguf": b"GGUF" + struct.pack("<IQQ", 3, 100, 0)}))
    # one tensor entry whose data offset points past the end of the file
    entry = struct.pack("<Q", 1) + b"w" + struct.pack("<I", 1) + struct.pack("<Q", 4) + struct.pack("<IQ", 0, 1 << 20)
    assert "G226" in _codes(_scan(tmp_path / "c", {"m.gguf": b"GGUF" + struct.pack("<IQQ", 3, 1, 0) + entry + b"\0" * 32}))
    good = b"GGUF" + struct.pack("<IQQ", 3, 1, 0) + entry[:-8] + struct.pack("<Q", 0) + b"\0" * 32
    assert _codes(_scan(tmp_path / "d", {"m.gguf": good})) == {}


# --- round-4 fixes (2026-10-21): never vouch "ok" for a region not read and verified ----------
def test_keras_config_deflate_corrupt_is_a_gap_not_a_crash(tmp_path):
    # a DEFLATE-compressed config.json with a broken deflate stream: zlib.error must map to G225, not crash
    p = tmp_path / "d" / "m.keras"
    p.parent.mkdir()
    cfg = ('{"layers": [' + ",".join(['{"class_name": "Dense"}'] * 50) + "]}").encode()
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("metadata.json", "{}")
        z.writestr("config.json", cfg)
    raw = bytearray(p.read_bytes())
    with zipfile.ZipFile(p) as z:
        off = z.getinfo("config.json").header_offset
    namelen = struct.unpack_from("<H", raw, off + 26)[0]
    extralen = struct.unpack_from("<H", raw, off + 28)[0]
    raw[off + 30 + namelen + extralen] = 0x06  # invalid DEFLATE block type -> zlib.error on decompress
    p.write_bytes(bytes(raw))
    assert "G225" in _codes(static_checks.scan_tree(p.parent))


def test_dangerous_pickle_under_data_path_is_not_skipped(tmp_path):
    # a dangerous pickle at .../data/payload.bin was excluded by PATH alone; path is never the sole skip reason
    p = tmp_path / "d" / "weights.dat"
    p.parent.mkdir()
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("archive/data/payload.bin", _evil())
    c = _codes(static_checks.scan_tree(p.parent))
    assert "G222" in c and "payload.bin" in c["G222"][0].evidence


def test_proto0_trailing_stream_that_imports_then_truncates_is_broken(tmp_path):
    # a proto-0 GLOBAL (no 0x80 PROTO marker) after a valid stream, cut off before STOP: a loader runs the
    # import, so the tail is a cut-off stream (G224 + G225), not "ok" -- detection must not hinge on PROTO
    body = pickle.dumps(1, protocol=2) + b"ccollections\nOrderedDict\n"
    c = _codes(_scan(tmp_path, {"w.pth": body}))
    assert "G224" in c and "G225" in c


def test_gguf_tensor_data_shorter_than_declared_is_high(tmp_path):
    # 58-byte GGUF declaring a 1,000,000-element F32 tensor with one byte of data: shortfall -> G226
    entry = (struct.pack("<Q", 1) + b"w" + struct.pack("<I", 1) + struct.pack("<Q", 1_000_000)
             + struct.pack("<IQ", 0, 0))  # name "w", nd=1, dim=1e6, type F32, data offset 0
    body = b"GGUF" + struct.pack("<IQQ", 3, 1, 0) + entry + b"\x00"
    assert "G226" in _codes(_scan(tmp_path, {"m.gguf": body}))


def test_capped_non_pkl_member_is_a_gap_not_dropped(tmp_path):
    # a member parsed cleanly up to the read cap is a pickle we did not finish (G225), not "not a pickle":
    # a >16 MiB BINBYTES prefix before a __reduce__ payload must not slip through under a non-.pkl name
    p = tmp_path / "d" / "pytorch_model.bin"
    p.parent.mkdir()
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("archive/payload.bin", b"\x80\x04\x8e" + struct.pack("<Q", 1 << 40) + b"x")
    assert "G225" in _codes(static_checks.scan_tree(p.parent))
