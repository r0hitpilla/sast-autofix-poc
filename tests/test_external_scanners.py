import json
import os

import pytest

import external_scanners
from external_scanners import parse_gitleaks_json, parse_osv_json, REDACTED
from scanner import scan

SECRET = "fixture-only-not-a-credential"


def gitleaks_output(repo_file_line: str = f'aws_key = "{SECRET}"'):
    return json.dumps([{
        "Description": "AWS Access Key",
        "StartLine": 1,
        "EndLine": 1,
        "File": "config.py",
        "Secret": SECRET,
        "Match": repo_file_line,
        "RuleID": "aws-access-token",
    }])


def test_gitleaks_finding_never_contains_the_secret(tmp_path):
    (tmp_path / "config.py").write_text(f'aws_key = "{SECRET}"\n')
    [finding] = parse_gitleaks_json(gitleaks_output(), str(tmp_path))
    assert SECRET not in finding.snippet
    assert REDACTED in finding.snippet
    assert finding.rule_id == "gitleaks.aws-access-token"
    assert finding.cwe == "CWE-798"
    assert finding.severity == "High"


def test_gitleaks_no_leaks_is_empty():
    assert parse_gitleaks_json("") == []
    assert parse_gitleaks_json("null") == []


def osv_output(repo: str):
    return json.dumps({"results": [{
        "source": {"path": os.path.join(repo, "requirements.txt")},
        "packages": [{
            "package": {"name": "flask", "version": "3.0.0", "ecosystem": "PyPI"},
            "vulnerabilities": [{
                "id": "PYSEC-2026-1",
                "summary": "Session leak",
                "affected": [{
                    "package": {"name": "flask", "ecosystem": "PyPI"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [
                        {"introduced": "0"}, {"fixed": "3.0.1"},
                    ]}],
                }],
            }],
            "groups": [{"ids": ["PYSEC-2026-1"], "max_severity": "7.5"}],
        }],
    }]})


def test_osv_finding_points_at_manifest_line_with_fix_version(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests>=2\nFlask>=3.0.0\n")
    [finding] = parse_osv_json(osv_output(str(tmp_path)), str(tmp_path))
    assert finding.file == "requirements.txt"
    assert finding.line == 2
    assert finding.rule_id == "osv.PYSEC-2026-1"
    assert finding.cwe == "CWE-1395"
    assert finding.severity == "High"  # CVSS 7.5
    assert "3.0.1" in finding.message


@pytest.mark.parametrize("score,expected", [("9.8", "Critical"), ("7.5", "High"), ("5.0", "Medium"), ("2.1", "Low")])
def test_osv_severity_follows_cvss_bands(tmp_path, score, expected):
    (tmp_path / "requirements.txt").write_text("Flask>=3.0.0\n")
    raw = json.loads(osv_output(str(tmp_path)))
    raw["results"][0]["packages"][0]["groups"][0]["max_severity"] = score
    [finding] = parse_osv_json(json.dumps(raw), str(tmp_path))
    assert finding.severity == expected


def test_scan_default_engine_is_semgrep_only(monkeypatch):
    calls = []
    monkeypatch.setattr("scanner.run_semgrep", lambda repo, rules: calls.append("semgrep") or '{"results": []}')
    monkeypatch.setattr(external_scanners, "run_gitleaks", lambda repo: calls.append("gitleaks") or [])
    monkeypatch.setattr(external_scanners, "run_osv", lambda repo: calls.append("osv") or [])
    scan(".", [])
    assert calls == ["semgrep"]


def test_scan_runs_every_requested_engine(monkeypatch):
    calls = []
    monkeypatch.setattr("scanner.run_semgrep", lambda repo, rules: calls.append("semgrep") or '{"results": []}')
    monkeypatch.setattr(external_scanners, "run_gitleaks", lambda repo: calls.append("gitleaks") or [])
    monkeypatch.setattr(external_scanners, "run_osv", lambda repo: calls.append("osv") or [])
    scan(".", [], engines=("semgrep", "gitleaks", "osv"))
    assert calls == ["semgrep", "gitleaks", "osv"]


def test_scan_rejects_unknown_engine():
    with pytest.raises(ValueError):
        scan(".", [], engines=("nope",))


def test_missing_binary_is_an_error_not_a_silent_skip(monkeypatch):
    monkeypatch.setattr(external_scanners.shutil, "which", lambda name: None)
    with pytest.raises(RuntimeError, match="gitleaks is not installed"):
        external_scanners.run_gitleaks(".")
