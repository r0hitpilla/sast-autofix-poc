import json
import os
from unittest.mock import patch

from scanner import parse_semgrep_json, run_semgrep

FIXTURE_PATH = os.path.join(os.path.dirname(__file__), "fixtures", "semgrep_output.json")


def test_parse_semgrep_json_extracts_findings():
    with open(FIXTURE_PATH) as f:
        raw = f.read()

    findings = parse_semgrep_json(raw)

    assert len(findings) == 1
    finding = findings[0]
    # Repo-root-relative, not CWD-relative: run_semgrep scans "." from inside
    # the target repo so Finding.file shares GitPython's frame.
    assert finding.file == "app.py"
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


def test_run_semgrep_scans_dot_from_inside_the_target_repo():
    # Semgrep reports paths relative to the argument it was given. Scanning
    # "." with cwd=target_repo is what keeps Finding.file repo-root-relative
    # and therefore in the same frame as every repo.git.* call downstream.
    with patch("scanner.subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = '{"results": []}'

        run_semgrep("sample_vuln_app", ["p/security-audit"])

    cmd = mock_run.call_args[0][0]
    assert cmd[-1] == "."
    assert "sample_vuln_app" not in cmd
    assert mock_run.call_args.kwargs["cwd"] == "sample_vuln_app"


def test_snippet_is_read_from_the_file_when_semgrep_redacts_it(tmp_path):
    (tmp_path / "app.py").write_text("a = 1\nquery = f'{x}'\nrows = run(query)\nb = 2\n")
    raw = json.dumps({"results": [{
        "path": "app.py", "check_id": "r", "start": {"line": 2}, "end": {"line": 3},
        "extra": {"lines": "requires login", "message": "m", "metadata": {}},
    }]})

    [finding] = parse_semgrep_json(raw, str(tmp_path))

    assert finding.snippet == "query = f'{x}'\nrows = run(query)"


def test_local_rule_paths_resolve_against_the_config_dir(tmp_path):
    from config import resolve_ruleset

    (tmp_path / "rules").mkdir()
    assert resolve_ruleset("rules/", str(tmp_path)) == os.path.join(str(tmp_path), "rules/")
    assert resolve_ruleset("p/owasp-top-ten", str(tmp_path)) == "p/owasp-top-ten"
