from unittest.mock import MagicMock

from models import Finding
from triage import build_reasoning_prompt, route, triage_finding


def make_finding():
    return Finding(
        file="app.py",
        line=41,
        rule_id="python.flask.security.injection.sql-injection",
        cwe="CWE-89",
        message="Detected string-interpolated SQL query.",
        snippet="query = f\"SELECT ... WHERE username = '{username}'\"",
    )


def test_build_reasoning_prompt_includes_finding_details():
    finding = make_finding()
    prompt = build_reasoning_prompt(finding)

    assert finding.file in prompt
    assert str(finding.line) in prompt
    assert finding.message in prompt
    assert finding.snippet in prompt


def test_route_above_fix_threshold():
    assert route(0.85, threshold_fix=0.8, threshold_review=0.4) == "fix"


def test_route_in_review_band():
    assert route(0.6, threshold_fix=0.8, threshold_review=0.4) == "review"
    assert route(0.4, threshold_fix=0.8, threshold_review=0.4) == "review"
    assert route(0.8, threshold_fix=0.8, threshold_review=0.4) == "review"


def test_route_below_review_threshold():
    assert route(0.1, threshold_fix=0.8, threshold_review=0.4) == "reject"


def test_triage_finding_wires_reasoning_into_laya_state():
    finding = make_finding()
    ollama = MagicMock()
    ollama.generate.return_value = "This looks exploitable; no upstream sanitization."
    laya = MagicMock()
    laya.true_positive_score.return_value = 0.92

    result = triage_finding(finding, ollama, laya, threshold_fix=0.8, threshold_review=0.4)

    assert result.finding is finding
    assert result.llm_reasoning == "This looks exploitable; no upstream sanitization."
    assert result.laya_score == 0.92
    assert result.route == "fix"

    laya_call_state = laya.true_positive_score.call_args[0][0]
    assert "This looks exploitable" in laya_call_state
    assert finding.message in laya_call_state


def test_triage_finding_routes_to_review_on_ollama_failure():
    finding = make_finding()
    ollama = MagicMock()
    ollama.generate.side_effect = ConnectionError("ollama unreachable")
    laya = MagicMock()

    result = triage_finding(finding, ollama, laya, threshold_fix=0.8, threshold_review=0.4)

    assert result.route == "review"
    assert result.laya_score == 0.0
    laya.true_positive_score.assert_not_called()


def test_triage_finding_routes_to_review_on_laya_failure():
    finding = make_finding()
    ollama = MagicMock()
    ollama.generate.return_value = "reasoning text"
    laya = MagicMock()
    laya.true_positive_score.side_effect = RuntimeError("laya model error")

    result = triage_finding(finding, ollama, laya, threshold_fix=0.8, threshold_review=0.4)

    assert result.route == "review"
    assert result.laya_score == 0.0
    # The Ollama reasoning survives...
    assert "reasoning text" in result.llm_reasoning
    # ...and the Laya failure is recorded, so laya_score=0.0 can't be mistaken
    # for a genuine calibrated "definitely a false positive" score.
    assert "laya" in result.llm_reasoning.lower()
    assert "laya model error" in result.llm_reasoning
