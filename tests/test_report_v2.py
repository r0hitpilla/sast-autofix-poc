import json

from models import Finding, TriageResult, ValidationResult
from report import SCHEMA_VERSION, FindingRecord, RunReport, fingerprint, to_json


def finding(line=42, snippet="query = f'{x}'"):
    return Finding(file="app.py", line=line, rule_id="r.sqli", cwe="CWE-89", message="m",
                   snippet=snippet, severity="Critical", owasp=["A03:2021 - Injection"])


def test_fingerprint_ignores_line_moves_but_not_code_changes():
    assert fingerprint(finding(line=42)) == fingerprint(finding(line=60))
    assert fingerprint(finding(snippet="query =  f'{x}'")) == fingerprint(finding())
    assert fingerprint(finding(snippet="query = f'{y}'")) != fingerprint(finding())


def test_v2_report_carries_run_meta_triage_and_fix():
    f = finding()
    triage = TriageResult(f, "r", 0.92, "fix",
                          evidence=[("Initial analysis", "bad\nVERDICT: TRUE POSITIVE — raw SQL")])
    v = ValidationResult(f, True, "9 passed", True, attempts=2,
                         fix_diff="+ cursor.execute(q, (x,))\n", created_files=["templates/a.html"])
    report = RunReport(target="o/r @ SV", records=[FindingRecord(triage, "fixed and validated", v)])
    report.meta = {"run": {"id": "42", "base_branch": "SV"}, "pull_request": {"number": 7}}

    data = json.loads(to_json(report))

    assert data["schema_version"] == SCHEMA_VERSION == 2
    assert data["run"]["id"] == "42" and data["pull_request"]["number"] == 7
    rec = data["findings"][0]
    assert rec["fingerprint"] == fingerprint(f)
    assert rec["finding"]["severity"] == "Critical"
    assert rec["triage"]["llm_label"] == "tp" and rec["triage"]["rounds"] == 0
    assert rec["triage"]["evidence"][0]["key"] == "Initial analysis"
    assert rec["fix"]["attempts"] == 2 and rec["fix"]["created_files"] == ["templates/a.html"]
    assert rec["fix"]["last_proposal"] is None  # only kept for fixes that didn't validate
    assert data["summary"]["confirmed"] == 1 and data["summary"]["blocking"] == 1
