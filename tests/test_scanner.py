import json
import os

from scanner import parse_semgrep_json

FIXTURE_PATH = os.path.join(os.path.dirname(__file__), "fixtures", "semgrep_output.json")


def test_parse_semgrep_json_extracts_findings():
    with open(FIXTURE_PATH) as f:
        raw = f.read()

    findings = parse_semgrep_json(raw)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.file == "sample_vuln_app/app.py"
    assert finding.line == 41
    assert finding.rule_id == "python.flask.security.injection.sql-injection-using-db-cursor-execute"
    assert finding.cwe == "CWE-89: SQL Injection"
    assert "string-interpolated SQL query" in finding.message
    assert "SELECT id, username, role" in finding.snippet


def test_parse_semgrep_json_handles_missing_cwe():
    raw = json.dumps({
        "results": [{
            "check_id": "some.rule",
            "path": "a.py",
            "start": {"line": 1},
            "extra": {"message": "msg", "metadata": {}, "lines": "code"},
        }]
    })

    findings = parse_semgrep_json(raw)

    assert findings[0].cwe == "unknown"


def test_parse_semgrep_json_empty_results():
    raw = json.dumps({"results": []})
    assert parse_semgrep_json(raw) == []
