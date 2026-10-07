from datetime import timedelta

from sqlalchemy import select

from dashboard import queries
from dashboard.db import LlmCall
from dashboard.ingest import ingest

from .conftest import NOW, finding, report


def call(purpose="fix", model="qwen", provider="ollama", prompt=100, completion=40, ms=2000, ok=True, ref=None,
         at=None, truncated=False, error=None):
    return {"at": (at or NOW).isoformat(), "purpose": purpose, "model": model, "provider": provider,
            "prompt_tokens": prompt, "completion_tokens": completion, "duration_ms": ms, "ok": ok,
            "truncated": truncated, "ref": ref, "error": error}


def with_usage(r, calls):
    r["llm_usage"] = {"summary": {}, "calls": calls}
    return r


def test_a_runs_ai_calls_are_stored_with_the_run(Session):
    run = ingest(with_usage(report("u1"), [call(ref="app.py:1"), call(purpose="triage", prompt=500, completion=200)]), Session)
    with Session() as s:
        rows = s.scalars(select(LlmCall).where(LlmCall.run_id == run.id)).all()
    assert sorted(r.purpose for r in rows) == ["fix", "triage"]
    assert {r.ref for r in rows} == {"app.py:1", None}


def test_reingesting_a_run_does_not_double_count_its_calls(Session):
    r = with_usage(report("u2"), [call(), call()])
    ingest(r, Session)
    ingest(r, Session)
    with Session() as s:
        assert len(s.scalars(select(LlmCall)).all()) == 2


def test_reports_from_before_usage_tracking_still_ingest(Session):
    ingest(report("old"), Session)
    with Session() as s:
        assert queries.run_usage(s, "old")["totals"]["calls"] == 0
        assert queries.usage_overview(s)["totals"]["calls"] == 0


def test_one_malformed_call_does_not_lose_the_run(Session):
    r = with_usage(report("u3"), [call(), {"duration_ms": "not a number"}, call(purpose="review")])
    ingest(r, Session)
    with Session() as s:
        assert queries.run_usage(s, "u3")["totals"]["calls"] == 2


def test_totals_are_split_by_model_purpose_and_day(Session):
    yesterday = NOW - timedelta(days=1)
    ingest(with_usage(report("a", hours_ago=2), [
        call(purpose="triage", model="qwen", prompt=1000, completion=300, ms=4000),
        call(purpose="fix", model="coder", prompt=400, completion=100, ms=1000, ok=False, truncated=True, error="limit"),
        call(purpose="laya_triage", model="laya", provider="laya", prompt=None, completion=None, ms=300),
    ]), Session)
    ingest(with_usage(report("b", hours_ago=30), [call(purpose="fix", model="qwen", prompt=50, completion=20, at=yesterday)]), Session)
    with Session() as s:
        u = queries.usage_overview(s)
    t = u["totals"]
    assert (t["calls"], t["prompt_tokens"], t["completion_tokens"], t["total_tokens"], t["errors"]) == (4, 1450, 420, 1870, 1)
    assert u["runs"] == 2
    qwen = next(m for m in u["by_model"] if m["model"] == "qwen")
    assert (qwen["calls"], qwen["total_tokens"]) == (2, 1370)
    laya = next(m for m in u["by_model"] if m["model"] == "laya")
    assert laya["total_tokens"] == 0 and laya["calls"] == 1      # Laya reports no tokens
    assert u["by_model"][0]["model"] == "qwen"                    # heaviest first
    assert {p["purpose"] for p in u["by_purpose"]} == {"triage", "fix", "laya_triage"}
    assert len(u["by_day"]) == 2 and sum(d["calls"] for d in u["by_day"]) == 4
    assert u["top_runs"][0]["run_id"] == "a"


def test_dry_runs_and_other_repositories_are_left_out(Session):
    ingest(with_usage(report("real", repo="o/r"), [call()]), Session)
    ingest(with_usage(report("dry", repo="o/r", dry_run=True), [call()]), Session)
    ingest(with_usage(report("other", repo="x/y"), [call()]), Session)
    with Session() as s:
        assert queries.usage_overview(s)["totals"]["calls"] == 2
        assert queries.usage_overview(s, repository="o/r")["totals"]["calls"] == 1


def test_the_window_limits_which_runs_count(Session):
    ingest(with_usage(report("recent", hours_ago=1), [call()]), Session)
    ingest(with_usage(report("old", hours_ago=24 * 10), [call()]), Session)
    with Session() as s:
        assert queries.usage_overview(s, since=NOW - timedelta(days=3))["totals"]["calls"] == 1


def test_a_runs_detail_includes_its_usage_and_slowest_calls(client, Session):
    ingest(with_usage(report("det", hours_ago=1), [call(ms=500), call(purpose="review", ms=9000, ref="a.py:2")]), Session)
    detail = client.get("/api/runs/det").json()
    assert detail["usage"]["totals"]["calls"] == 2
    assert detail["usage"]["slowest"][0]["purpose"] == "review"


def test_the_usage_endpoint_needs_a_session_and_validates_its_window(client):
    assert client.get("/api/usage?days=7").status_code == 200
    assert client.get("/api/usage?days=0").status_code == 422
    from fastapi.testclient import TestClient
    from dashboard import api
    assert TestClient(api.app).get("/api/usage").status_code == 401
