from unittest.mock import patch

import pytest

from history import fetch_policy
from identity import finding_fingerprint
from models import Finding, TriageResult
from policy import STRICT, PolicyError, from_dict
from report import FindingRecord, RunReport

ALL_BLOCK = {"Critical": "block", "High": "block", "Medium": "block", "Low": "block"}


def policy(**overrides):
    data = {"severity_actions": dict(ALL_BLOCK), **overrides}
    return from_dict(data, version=3)


def finding(severity="High", file="app.py"):
    return Finding(file=file, line=1, rule_id="r", cwe="CWE-79", message="m", snippet="x", severity=severity)


def test_strict_blocks_everything_and_ignores_decisions():
    assert STRICT.blocks("Low", None) and STRICT.blocks("Critical", "false_positive")


def test_allow_never_blocks_and_review_clears_with_a_decision():
    p = policy(severity_actions={**ALL_BLOCK, "Low": "allow", "Medium": "review"})
    assert not p.blocks("Low", None)
    assert p.blocks("Medium", None) and not p.blocks("Medium", "false_positive")
    assert p.blocks("High", "false_positive")  # block isn't cleared by a decision by default


def test_a_policy_can_let_decisions_clear_blocks():
    assert not policy(decisions_clear_blocks=True).blocks("Critical", "suppressed")


def test_never_autofix_paths_and_ci_files_always_excluded():
    p = policy(never_autofix=["infra/**", "*.tf"])
    assert not p.may_autofix("infra/main/net.py") and not p.may_autofix("vpc.tf")
    assert p.may_autofix("app.py")
    assert not policy(never_autofix=[]).may_autofix(".github/workflows/ci.yml")
    assert not policy(autofix=False).may_autofix("app.py")


def test_scope_by_repository_and_branch():
    p = policy(repositories=["acme/payments-*"], branches=["main", "release/*"])
    assert p.applies_to("acme/payments-api", "release/2.1")
    assert not p.applies_to("acme/web", "main") and not p.applies_to("acme/payments-api", "feature/x")


@pytest.mark.parametrize("bad", [
    {"severity_actions": {"Critical": "block"}},
    {"severity_actions": {**ALL_BLOCK, "Low": "ignore"}},
])
def test_invalid_policies_are_refused(bad):
    with pytest.raises(PolicyError):
        from_dict(bad)


def test_report_gate_follows_the_policy_and_decisions():
    low, high = finding("Low"), finding("High", file="b.py")
    rr = RunReport(target="o/r @ SV", records=[
        FindingRecord(TriageResult(low, "r", 0.9, "fix"), "x"),
        FindingRecord(TriageResult(high, "r", 0.9, "fix"), "x"),
    ])
    rr.meta = {"run": {"repository": "o/r"}}
    assert len(rr.blocking) == 2  # strict default
    rr.policy = policy(severity_actions={**ALL_BLOCK, "Low": "allow", "High": "review"})
    assert [r.triage.finding for r in rr.blocking] == [high]
    rr.decisions = {finding_fingerprint("o/r", "r", "b.py", "x"): "false_positive"}
    assert rr.blocking == []


def test_unreachable_dashboard_means_the_strict_policy():
    import urllib.error
    with patch("history.urllib.request.urlopen", side_effect=urllib.error.URLError("down")):
        assert fetch_policy("http://127.0.0.1:1", "o/r", "main") is STRICT
    assert fetch_policy(None, "o/r", "main") is STRICT
