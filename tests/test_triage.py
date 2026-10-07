from unittest.mock import MagicMock

from models import Finding
from triage import INVESTIGATION_QUESTIONS, build_reasoning_prompt, route, triage_finding


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
    laya.assess.return_value = (0.92, "input_source")

    result = triage_finding(finding, ollama, laya, threshold_fix=0.8, threshold_review=0.4)

    assert result.finding is finding
    assert "This looks exploitable" in result.llm_reasoning
    assert result.laya_score == 0.92
    assert result.route == "fix"
    # Confident on the first pass: no follow-up questions spent.
    assert ollama.generate.call_count == 1
    assert laya.assess.call_count == 1

    laya_call_state = laya.assess.call_args[0][0]
    assert "This looks exploitable" in laya_call_state
    assert finding.message in laya_call_state


def test_laya_drives_followup_questions_until_confident():
    finding = make_finding()
    ollama = MagicMock()
    ollama.generate.side_effect = [
        "initial analysis",
        "username comes straight from request.args",
        "nothing escapes or parameterizes it",
    ]
    laya = MagicMock()
    laya.assess.side_effect = [
        (0.6, "input_source"),   # unsure -> asks about the input source
        (0.7, "sanitization"),   # still unsure -> asks about sanitization
        (0.95, "reachability"),  # confident -> stops, choice ignored
    ]

    result = triage_finding(finding, ollama, laya, threshold_fix=0.8, threshold_review=0.4)

    assert result.route == "fix"
    assert result.laya_score == 0.95
    assert [q for q, _ in result.evidence][0] == "Initial analysis"
    assert result.evidence[1][0] == INVESTIGATION_QUESTIONS["input_source"][1]
    assert result.evidence[2][0] == INVESTIGATION_QUESTIONS["sanitization"][1]
    # The LLM's answers are what Laya scores next...
    assert "request.args" in laya.assess.call_args_list[1][0][0]
    # ...and Laya is never offered a question it already asked.
    third_options = laya.assess.call_args_list[2][0][2]
    assert "input_source" not in third_options
    assert "sanitization" not in third_options


def test_laya_stops_asking_after_max_rounds():
    finding = make_finding()
    ollama = MagicMock()
    ollama.generate.return_value = "inconclusive"
    laya = MagicMock()
    laya.assess.side_effect = [(0.6, "input_source"), (0.6, "sanitization")]

    result = triage_finding(
        finding, ollama, laya, threshold_fix=0.8, threshold_review=0.4, max_rounds=1,
    )

    assert result.route == "review"
    assert ollama.generate.call_count == 2  # initial + 1 follow-up
    # Out of rounds: the final pass offers Laya nothing more to ask.
    assert laya.assess.call_args_list[-1][0][2] == {}


def test_triage_finding_routes_to_review_on_ollama_failure():
    finding = make_finding()
    ollama = MagicMock()
    ollama.generate.side_effect = ConnectionError("ollama unreachable")
    laya = MagicMock()

    result = triage_finding(finding, ollama, laya, threshold_fix=0.8, threshold_review=0.4)

    assert result.route == "review"
    assert result.laya_score == 0.0
    laya.assess.assert_not_called()


def test_triage_finding_routes_to_review_on_laya_failure():
    finding = make_finding()
    ollama = MagicMock()
    ollama.generate.return_value = "reasoning text"
    laya = MagicMock()
    laya.assess.side_effect = RuntimeError("laya model error")

    result = triage_finding(finding, ollama, laya, threshold_fix=0.8, threshold_review=0.4)

    assert result.route == "review"
    assert result.laya_score == 0.0
    # The Ollama reasoning survives...
    assert "reasoning text" in result.llm_reasoning
    # ...and the Laya failure is recorded, so laya_score=0.0 can't be mistaken
    # for a genuine calibrated "definitely a false positive" score.
    assert "laya" in result.llm_reasoning.lower()
    assert "laya model error" in result.llm_reasoning


def test_laya_state_keeps_evidence_compact_and_ahead_of_code():
    from triage import build_laya_state

    finding = make_finding()
    long_answer = "blah " * 400 + "\nVERDICT: username flows unescaped into the SQL string."
    state = build_laya_state(finding, [
        ("Initial analysis", long_answer),
        (INVESTIGATION_QUESTIONS["sanitization"][1], "**VERDICT:** nothing sanitizes it"),
    ])

    assert "- Initial analysis: username flows unescaped into the SQL string." in state
    assert "- sanitization: nothing sanitizes it" in state
    assert "blah" not in state
    assert state.index("sanitization") < state.index("Flagged code")
    assert len(state) < 1500


def test_answer_without_verdict_is_capped():
    from triage import summarize_answer

    assert len(summarize_answer("x " * 500)) <= 240


def test_reject_needs_laya_and_the_llm_to_agree():
    from triage import decide

    # Laya low but the LLM says it's real -> a human decides; never dropped.
    assert decide(0.37, "tp", 0.8, 0.4) == "review"
    # Laya low, LLM gave no label -> a human decides.
    assert decide(0.2, None, 0.8, 0.4) == "review"
    # Both say false positive -> reject.
    assert decide(0.2, "fp", 0.8, 0.4) == "reject"


def test_llm_true_positive_plus_unsure_laya_is_fixed():
    from triage import decide

    assert decide(0.80, "tp", 0.8, 0.4) == "fix"   # the SQLi that went to review
    assert decide(0.80, None, 0.8, 0.4) == "review"
    assert decide(0.95, "fp", 0.8, 0.4) == "review"  # disagreement: a person decides, not a fix


def test_llm_label_parses_the_verdict_line():
    from triage import llm_label

    assert llm_label("blah\nVERDICT: TRUE POSITIVE — unescaped input") == "tp"
    assert llm_label("**VERDICT:** False positive — constant string") == "fp"
    assert llm_label("no verdict here") is None


def test_triage_rejects_only_when_llm_also_says_false_positive():
    finding = make_finding()
    ollama = MagicMock()
    ollama.generate.return_value = "Exploitable.\nVERDICT: TRUE POSITIVE — raw SQL"
    laya = MagicMock()
    laya.assess.return_value = (0.37, None)

    result = triage_finding(finding, ollama, laya, threshold_fix=0.8, threshold_review=0.4)

    assert result.route != "reject"
