from hallucination import check_references, declared_import_names, pypi_version_exists, unpublished_versions
from models import Finding
from playbooks import DEPENDENCY_VULNERABILITY, HARD_CODED_SECRET, PASSWORD_HASHING, guidance_for
from risk import risk_score, by_risk
from triage import TriageResult  # noqa: F401  (import check: triage module loads)


def finding(**kwargs):
    base = dict(file="app.py", line=1, rule_id="r", cwe="CWE-000", message="m",
                snippet="", severity="Medium")
    base.update(kwargs)
    return Finding(**base)


# ------------------------------------------------------------ hallucination

def test_stdlib_and_declared_imports_resolve():
    after = "import os\nimport flask\nfrom yaml import safe_load\n"
    problems = check_references("app.py", "", after, None, "Flask>=3.0\nPyYAML>=6\n")
    assert problems == []


def test_invented_import_is_rejected():
    after = "import os\nimport fastjson\n"
    [problem] = check_references("app.py", "import os\n", after, None, "")
    assert "fastjson" in problem


def test_import_already_in_the_file_is_not_held_against_the_fix():
    before = "import legacy_thing\n"
    after = "import legacy_thing\nimport os\n"
    assert check_references("app.py", before, after, None, "") == []


def test_local_module_resolves(tmp_path):
    (tmp_path / "helpers.py").write_text("")
    assert check_references("app.py", "", "from helpers import x\n", str(tmp_path), "") == []


def test_declared_import_names_map_distribution_to_import():
    names = declared_import_names("PyYAML>=6\npython-dateutil\nFlask\n")
    assert {"yaml", "dateutil", "flask"} <= names


def test_unpublished_pin_is_rejected():
    exists = lambda name, version: version != "9.9.9"
    problems = unpublished_versions("Flask>=3.0.0\n", "Flask>=9.9.9\n", exists)
    assert problems == ["flask 9.9.9 is not a published version on PyPI"]


def test_unchanged_pin_is_not_rechecked():
    calls = []
    unpublished_versions("Flask>=3.0.0\n", "Flask>=3.0.0\n", lambda n, v: calls.append(v) or False)
    assert calls == []


def test_unreachable_index_is_not_treated_as_fake(monkeypatch):
    import urllib.error
    def boom(*args, **kwargs):
        raise urllib.error.URLError("offline")
    monkeypatch.setattr("hallucination.urllib.request.urlopen", boom)
    assert pypi_version_exists("flask", "3.0.1") is None


# -------------------------------------------------------------- playbooks

def test_md5_password_hash_gets_password_playbook():
    f = finding(cwe="CWE-327", snippet="    return hashlib.md5(password.encode()).hexdigest()")
    assert guidance_for(f) == PASSWORD_HASHING
    assert "salt" in PASSWORD_HASHING and "scrypt" in PASSWORD_HASHING


def test_md5_outside_password_code_gets_no_playbook():
    f = finding(cwe="CWE-327", snippet="    return hashlib.md5(blob).hexdigest()")
    assert guidance_for(f) == ""


def test_dependency_and_secret_playbooks():
    assert guidance_for(finding(rule_id="osv.PYSEC-1")) == DEPENDENCY_VULNERABILITY
    assert guidance_for(finding(rule_id="gitleaks.aws")) == HARD_CODED_SECRET


# ------------------------------------------------------------------- risk

def test_request_facing_code_outranks_same_severity_internal_code():
    exposed = finding(severity="High", snippet="name = request.args.get('name')")
    internal = finding(severity="High", snippet="x = compute()")
    assert risk_score(exposed) > risk_score(internal)


def test_by_risk_orders_highest_first():
    low = TriageResult(finding=finding(severity="Low"), llm_reasoning="", laya_score=0.9, route="fix")
    crit = TriageResult(finding=finding(severity="Critical"), llm_reasoning="", laya_score=0.9, route="fix")
    assert [t.finding.severity for t in by_risk([low, crit])] == ["Critical", "Low"]


def test_stdlib_attribute_that_does_not_exist_is_rejected():
    from hallucination import unknown_stdlib_attributes
    after = "import hashlib\nok = hashlib.compare_digest(a, b)\n"
    [problem] = unknown_stdlib_attributes("app.py", "import hashlib\n", after)
    assert "hashlib.compare_digest" in problem


def test_real_stdlib_attribute_passes():
    from hallucination import unknown_stdlib_attributes
    after = "import hmac\nimport hashlib\nok = hmac.compare_digest(a, b)\nd = hashlib.scrypt(b'x')\n"
    assert unknown_stdlib_attributes("app.py", "", after) == []
