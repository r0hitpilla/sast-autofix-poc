import sys
from unittest.mock import MagicMock, patch

# Fallback: create fake laya module if not installed
if 'laya' not in sys.modules:
    fake_laya = MagicMock()
    sys.modules['laya'] = fake_laya

from laya_client import LayaClient


def test_true_positive_score_extracts_noul_value():
    with patch("laya_client.laya.load") as mock_load:
        mock_agent = MagicMock()
        mock_agent.predict.return_value = {
            "true_positive": {"noul": 0.91}
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
        assert questions[0]["key"] == "true_positive"
        assert questions[0]["type"] == "noul"
        assert questions[0]["instructions"] == "is this a true positive security vulnerability"
