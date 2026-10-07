from unittest.mock import MagicMock, patch

from laya_client import LayaClient


def test_true_positive_score_extracts_noul_value():
    with patch("laya_client.laya.load") as mock_load:
        mock_agent = MagicMock()
        mock_agent.predict.return_value = {
            "answers": {
                "true_positive": {"noul": 0.91}
            }
        }
        mock_load.return_value = mock_agent

        client = LayaClient(model="convaiinnovations/laya")
        score = client.true_positive_score(
            state="finding + llm reasoning text",
            question="is this a true positive security vulnerability",
        )

        assert score == 0.91
        mock_agent.predict.assert_called_once()
        call_args = mock_agent.predict.call_args
        assert call_args[0][0] == "finding + llm reasoning text"
        questions = call_args[0][1]
        assert isinstance(questions, dict)
        assert "true_positive" in questions
        assert questions["true_positive"]["type"] == "noul"
        assert questions["true_positive"]["instructions"] == "is this a true positive security vulnerability"


def test_assess_returns_score_and_chosen_next_question():
    with patch("laya_client.laya.load") as mock_load:
        mock_agent = MagicMock()
        mock_agent.predict.return_value = {
            "answers": {
                "true_positive": {"noul": 0.55},
                "next_question": {"choice": "sanitization"},
            }
        }
        mock_load.return_value = mock_agent

        client = LayaClient(model="convaiinnovations/laya")
        score, choice = client.assess(
            "state", "is this a true positive", {"sanitization": "is it escaped"},
        )

        assert (score, choice) == (0.55, "sanitization")
        questions = mock_agent.predict.call_args[0][1]
        assert questions["next_question"]["type"] == "choice"
        assert questions["next_question"]["criteria"] == {"sanitization": "is it escaped"}


def test_assess_with_no_options_only_scores():
    with patch("laya_client.laya.load") as mock_load:
        mock_agent = MagicMock()
        mock_agent.predict.return_value = {"answers": {"true_positive": {"noul": 0.3}}}
        mock_load.return_value = mock_agent

        score, choice = LayaClient(model="m").assess("state", "q", {})

        assert (score, choice) == (0.3, None)
        assert "next_question" not in mock_agent.predict.call_args[0][1]


def test_laya_calls_are_recorded_with_their_purpose_but_no_token_counts():
    from unittest.mock import MagicMock, patch
    from laya_client import LayaClient
    from llm_usage import tag

    with patch("laya_client.laya.load", return_value=MagicMock()) as load:
        load.return_value.predict.return_value = {"answers": {"true_positive": {"noul": 0.83}}}
        client = LayaClient("laya-model")
        with tag(purpose="laya_triage", ref="app.py:98"):
            score, choice = client.assess("state", "q", {})
    assert (score, choice) == (0.83, None)
    [call] = client.usage.calls()
    assert (call.purpose, call.provider, call.ref) == ("laya_triage", "laya", "app.py:98")
    assert call.prompt_tokens is None and call.ok


def test_a_failing_laya_call_is_recorded_and_re_raised():
    from unittest.mock import MagicMock, patch
    import pytest
    from laya_client import LayaClient

    with patch("laya_client.laya.load", return_value=MagicMock()) as load:
        load.return_value.predict.side_effect = RuntimeError("gpu error")
        client = LayaClient("laya-model")
        with pytest.raises(RuntimeError):
            client.assess("state", "q", {})
    assert not client.usage.calls()[0].ok
