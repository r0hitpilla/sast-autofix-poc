import json

from models import Finding, Hunk, TriageResult, ValidationResult
from pr import build_line_comments, proof_line
from report import FindingRecord, RunReport, to_json, to_markdown

TEST_PATH = "tests/test_security_cwe79_vuln_2.py"


def finding():
    return Finding(file="vuln.py", line=2, rule_id="r", cwe="CWE-79", message="m", snippet="s")


def validation(proof):
    return ValidationResult(finding=finding(), clean=True, test_output="9 passed", validated=True, attempts=1,
                            fix_diff="+x\n", proof=proof)


def test_a_proven_fix_says_which_test_backs_it():
    text = proof_line(validation({"status": "proven", "test": TEST_PATH}))
    assert "✅" in text and TEST_PATH in text and "regression test" in text
    assert "not that every variant is" in text      # one attack, not a guarantee


def test_a_refuted_fix_is_called_out_loudly_with_the_test_output():
    text = proof_line(validation({"status": "refuted", "test": TEST_PATH, "fixed_output": "assert 1 == 2"}))
    assert "❌" in text and "still works" in text and "assert 1 == 2" in text


def test_an_unproven_fix_makes_no_claim_and_says_why():
    text = proof_line(validation({"status": "unproven", "reason": "No valid exploit test after 3 attempt(s)."}))
    assert "not shown" in text and "No valid exploit test" in text and "✅" not in text


def test_no_proof_line_when_the_scanner_is_the_proof_or_proofs_are_off():
    assert proof_line(validation({"status": "not_applicable"})) == ""
    assert proof_line(validation({"status": "off"})) == ""
    assert proof_line(validation(None)) == ""


def test_the_regression_tests_own_lines_get_their_own_comment_not_a_fix_comment():
    triage = TriageResult(finding=finding(), llm_reasoning="r", laya_score=0.9, route="fix")
    v = validation({"status": "proven", "test": TEST_PATH})
    v.created_files = [TEST_PATH]
    v.fix_diff = "--- a/vuln.py\n+++ b/vuln.py\n@@ -1 +1 @@\n-bad\n+good_line\n"
    v.fix_diff += f"--- /dev/null\n+++ b/{TEST_PATH}\n@@ -0,0 +1,2 @@\n+def test_proof_x():\n+    assert 1\n"
    hunks = [Hunk(file="vuln.py", old_start=1, old_count=1, new_start=1, new_count=1, removed=["bad"], added=["good_line"]),
             Hunk(file=TEST_PATH, old_start=0, old_count=0, new_start=1, new_count=2, added=["def test_proof_x():", "assert 1"])]
    comments = {c["path"]: c["body"] for c in build_line_comments([(triage, v)], hunks)}
    assert "regression test" in comments[TEST_PATH] and "fixes **CWE-79**" in comments["vuln.py"]


def test_the_report_carries_the_proof_and_counts_proven_fixes():
    triage = TriageResult(finding=finding(), llm_reasoning="r", laya_score=0.9, route="fix")
    rr = RunReport(target="o/r @ main", records=[
        FindingRecord(triage, "fixed and validated", validation({"status": "proven", "test": TEST_PATH, "code": "def test_proof_x(): ..."})),
        FindingRecord(triage, "fixed and validated", validation({"status": "unproven", "reason": "x"})),
    ])
    data = json.loads(to_json(rr))
    assert data["summary"]["proven"] == 1
    assert data["findings"][0]["fix"]["proof"]["status"] == "proven"
    md = to_markdown(rr)
    assert "| Proof |" in md and "| proven |" in md and "| unproven |" in md
