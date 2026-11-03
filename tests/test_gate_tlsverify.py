"""G230 (code / command that switches TLS certificate verification off).

Trees are synthetic. Each check has a benign counterpart that must stay clean.
"""

from __future__ import annotations

from pathlib import Path

from zee.gate import static_checks


def _scan(tmp_path: Path, files: dict[str, str]):
    for rel, body in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return {f.code: f for f in static_checks.scan_tree(tmp_path)}


BAD = {
    "a.py": "r = requests.get(u, verify=False)\n",
    "b.js": "new https.Agent({ rejectUnauthorized: false })\n",
    "c.go": "tls.Config{InsecureSkipVerify: true}\n",
    "d.sh": "curl -sSLk https://x.example/i | tee /tmp/o\n",
    "e.sh": "wget --no-check-certificate https://x.example/f\n",
    "f.sh": "export NODE_TLS_REJECT_UNAUTHORIZED=0\n",
    "g.py": "ctx = ssl._create_unverified_context()\n",
    "h.sh": "git config --global http.sslVerify false\n",
}


def test_each_pattern_is_medium(tmp_path):
    for name, body in BAD.items():
        by = _scan(tmp_path / name, {name: body})
        assert by["G230"].severity.value == "medium", name


def test_benign_stays_clean(tmp_path):
    by = _scan(tmp_path, {
        "a.py": "requests.get(u, verify=True)\nverify = cert_path\n# verify=False in a comment\n",
        "b.js": "new https.Agent({ rejectUnauthorized: true })\n",
        "c.sh": "curl --keepalive-time 5 -o out -sS https://x.example\n",
        "README.md": "run `curl -k https://localhost` only for a local test\n",
    })
    assert "G230" not in by


def test_test_paths_are_low(tmp_path):
    by = _scan(tmp_path, {"tests/test_x.py": "requests.get(u, verify=False)\n"})
    assert by["G230"].severity.value == "low"


def test_skill_procedure_doc_is_scanned_but_readme_is_not(tmp_path):
    by = _scan(tmp_path, {"skills/x/SKILL.md": "Run `curl -k https://x.example/i` first.\n"})
    assert by["G230"].severity.value == "medium"
    by = _scan(tmp_path / "r", {"README.md": "Run `curl -k https://x.example/i` first.\n"})
    assert "G230" not in by


def test_git_ssl_no_verify_needs_an_on_value(tmp_path):
    assert "G230" not in _scan(tmp_path, {"a.sh": "export GIT_SSL_NO_VERIFY=false\n"})
    assert "G230" in _scan(tmp_path / "b", {"a.sh": "export GIT_SSL_NO_VERIFY=1\n"})


def test_verify_false_needs_a_network_word_nearby(tmp_path):
    assert "G230" not in _scan(tmp_path, {"a.py": "df = df.take(idx, axis=0, verify=False)\n"})


# --- regressions: long lines, quoted keys, curl option arguments, unparsable stores, exit codes ---

def test_long_line_is_still_scanned(tmp_path):
    body = "var a=1;" * 400 + " new https.Agent({rejectUnauthorized: false}); " + "var b=2;" * 400 + "\n"
    assert "G230" in _scan(tmp_path, {"min.js": body})


def test_quoted_key_is_detected(tmp_path):
    for i, body in enumerate(['{"rejectUnauthorized": false}\n', "{'strictSSL': false}\n", '{"InsecureSkipVerify": true}\n']):
        assert "G230" in _scan(tmp_path / str(i), {"a.js": body}), body




def test_curl_option_argument_is_not_a_flag(tmp_path):
    for i, body in enumerate(["curl -o -keep example.test\n", "curl -H -k example.test\n",
                              "curl --output -k example.test\n", "curl -XPOST example.test\n"]):
        assert "G230" not in _scan(tmp_path / str(i), {"a.sh": body}), body
    for i, body in enumerate(["curl -o out -k example.test\n", "curl -XPOST -k example.test\n",
                              "curl -sSLk example.test\n", "curl --insecure example.test\n"]):
        assert "G230" in _scan(tmp_path / f"b{i}", {"a.sh": body}), body
