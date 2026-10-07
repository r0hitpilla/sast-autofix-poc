from datetime import timedelta
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from dashboard import api
from dashboard.auth import hash_password
from dashboard.db import AuditEvent, LlmCall, User
from dashboard.ingest import ingest
from dashboard.sources import langfuse

from .conftest import NOW, report

TRACE, SPAN = "a" * 32, "b" * 16


def call(offset_s=0, purpose="fix", traced=True, ms=2000, ref="app.py:98"):
    return {"at": (NOW + timedelta(seconds=offset_s)).isoformat(), "purpose": purpose, "model": "qwen",
            "provider": "ollama", "prompt_tokens": 100, "completion_tokens": 40, "duration_ms": ms, "ok": True,
            "ref": ref, "trace_id": TRACE if traced else None, "span_id": SPAN if traced else None}


def seed(Session, run_id="ai1", calls=None):
    r = report(run_id)
    r["llm_usage"] = {"summary": {}, "calls": calls if calls is not None else [call(0), call(5, "review"), call(9, "laya_triage", ms=300)]}
    ingest(r, Session)
    with Session() as s:
        return [c.id for c in s.scalars(select(LlmCall).where(LlmCall.run_id == run_id).order_by(LlmCall.id))]


@pytest.fixture
def creds(monkeypatch):
    monkeypatch.setattr(langfuse, "credentials", lambda *a, **k: ("http://lf.test", "pk", "sk"))


def person(Session, name, role):
    with Session() as s:
        s.add(User(email=f"{name}@x.io", name=name, role=role, password_hash=hash_password("a long enough password"),
                   active=True, created_at=NOW))
        s.commit()
    c = TestClient(api.app)
    assert c.post("/api/auth/login", json={"name": name, "password": "a long enough password"}).status_code == 200
    return c


# ---- the timeline ---------------------------------------------------------------

def test_trace_ids_are_stored_with_each_call(Session):
    seed(Session)
    with Session() as s:
        assert {(c.trace_id, c.span_id) for c in s.scalars(select(LlmCall))} == {(TRACE, SPAN)}


def test_the_timeline_is_in_order_with_offsets_from_the_first_call(client, Session, creds):
    seed(Session, calls=[call(9, "laya_triage"), call(0, "triage"), call(5, "fix")])
    data = client.get("/api/runs/ai1/ai").json()
    assert [(c["purpose"], c["offset_s"]) for c in data["calls"]] == [("triage", 0.0), ("fix", 5.0), ("laya_triage", 9.0)]
    assert all(set(c) >= {"duration_ms", "prompt_tokens", "model", "ref", "traced"} for c in data["calls"])


def test_internal_ids_are_not_sent_to_the_browser_only_ready_made_links(client, Session, creds):
    seed(Session)
    data = client.get("/api/runs/ai1/ai").json()
    text = str(data)
    assert SPAN not in text.replace(f"observation={SPAN}", "")      # the raw id appears only inside a link
    assert data["calls"][0]["link"].endswith(f"/traces/{TRACE}?observation={SPAN}")
    assert data["langfuse"]["trace_url"].endswith(f"/traces/{TRACE}")
    assert data["langfuse"]["connected"] is True


def test_runs_without_tracing_have_a_timeline_but_no_links(client, Session, creds):
    seed(Session, calls=[call(0, traced=False)])
    data = client.get("/api/runs/ai1/ai").json()
    assert data["calls"][0]["traced"] is False and data["calls"][0]["link"] is None
    assert data["langfuse"]["trace_url"] is None


def test_an_unknown_run_is_a_404(client):
    assert client.get("/api/runs/nope/ai").status_code == 404


def test_the_timeline_says_whether_this_person_may_read_prompts(client, Session, creds):
    seed(Session)
    dev = person(Session, "dev", "developer")
    assert client.get("/api/runs/ai1/ai").json()["langfuse"]["can_read_content"] is True      # admin
    assert dev.get("/api/runs/ai1/ai").json()["langfuse"]["can_read_content"] is False


def test_the_timeline_needs_a_session(Session):
    seed(Session)
    assert TestClient(api.app).get("/api/runs/ai1/ai").status_code == 401


# ---- prompts and replies ---------------------------------------------------------

def test_content_is_fetched_for_people_with_permission_and_the_view_is_audited(client, Session, monkeypatch):
    ids = seed(Session)
    monkeypatch.setattr(langfuse, "fetch_content", lambda t, s: {"available": True, "input": "the prompt", "output": "the reply"})
    eng = person(Session, "eng", "security_engineer")
    r = eng.get(f"/api/ai-calls/{ids[0]}/content")
    assert r.status_code == 200 and r.json()["input"] == "the prompt"
    assert r.headers["cache-control"] == "no-store"
    with Session() as s:
        event = s.scalar(select(AuditEvent).where(AuditEvent.action == "ai_content_viewed"))
    assert event.actor_email == "eng@x.io" and "ai1" in event.target and event.detail == {"call": ids[0]}


@pytest.mark.parametrize("role", ["developer", "auditor"])
def test_prompts_contain_source_code_so_other_roles_are_refused(client, Session, monkeypatch, role):
    ids = seed(Session)
    monkeypatch.setattr(langfuse, "fetch_content", lambda t, s: pytest.fail("must not be fetched"))
    assert person(Session, role, role).get(f"/api/ai-calls/{ids[0]}/content").status_code == 403


def test_an_untraced_call_has_no_content_and_nothing_is_fetched(client, Session, monkeypatch):
    ids = seed(Session, calls=[call(0, traced=False)])
    monkeypatch.setattr(langfuse, "fetch_content", lambda t, s: pytest.fail("must not be fetched"))
    assert client.get(f"/api/ai-calls/{ids[0]}/content").json()["available"] is False


def test_an_unknown_call_is_a_404(client):
    assert client.get("/api/ai-calls/999999/content").status_code == 404


# ---- talking to Langfuse ---------------------------------------------------------

class FakeGet:
    def __init__(self, pages):
        self.pages, self.calls = list(pages), []

    def __call__(self, url, params=None, auth=None, timeout=None):
        self.calls.append((url, params, auth))
        page = self.pages.pop(0)
        if isinstance(page, Exception):
            raise page
        return SimpleNamespace(raise_for_status=lambda: None, json=lambda: page)


@pytest.fixture
def lf(monkeypatch):
    langfuse.fetch_content.cache_clear()
    monkeypatch.setattr(langfuse, "credentials", lambda *a, **k: ("http://lf.test", "pk", "sk"))


def obs(span=SPAN, **kw):
    return {"id": span, "input": "p", "output": "r", **kw}


def test_content_is_read_from_the_observation_with_the_servers_keys(lf, monkeypatch):
    get = FakeGet([{"data": [obs("c" * 16), obs()], "meta": {}}])
    monkeypatch.setattr(langfuse.httpx, "get", get)
    assert langfuse.fetch_content(TRACE, SPAN) == {"available": True, "input": "p", "output": "r", "truncated": False}
    url, params, auth = get.calls[0]
    assert url == "http://lf.test/api/public/v2/observations" and params["traceId"] == TRACE and auth == ("pk", "sk")


def test_later_pages_are_searched_too(lf, monkeypatch):
    monkeypatch.setattr(langfuse.httpx, "get", FakeGet([{"data": [obs("c" * 16)], "meta": {"cursor": "n"}}, {"data": [obs()], "meta": {}}]))
    assert langfuse.fetch_content(TRACE, SPAN)["available"] is True


def test_a_call_langfuse_does_not_know_is_reported_not_raised(lf, monkeypatch):
    monkeypatch.setattr(langfuse.httpx, "get", FakeGet([{"data": [], "meta": {}}]))
    out = langfuse.fetch_content(TRACE, SPAN)
    assert out["available"] is False and "no record" in out["reason"]


def test_metadata_only_tracing_has_no_text_to_show(lf, monkeypatch):
    monkeypatch.setattr(langfuse.httpx, "get", FakeGet([{"data": [{"id": SPAN, "input": None, "output": None}], "meta": {}}]))
    assert "capture_content off" in langfuse.fetch_content(TRACE, SPAN)["reason"]


def test_a_down_langfuse_is_unavailable_not_an_error_page(lf, monkeypatch):
    monkeypatch.setattr(langfuse.httpx, "get", FakeGet([httpx.ConnectError("refused")]))
    out = langfuse.fetch_content(TRACE, SPAN)
    assert out["available"] is False and "could not be reached" in out["reason"]


def test_very_long_text_is_cut_and_marked(lf, monkeypatch):
    monkeypatch.setattr(langfuse.httpx, "get", FakeGet([{"data": [obs(input="x" * (langfuse.MAX_CHARS + 50))], "meta": {}}]))
    out = langfuse.fetch_content(TRACE, SPAN)
    assert len(out["input"]) == langfuse.MAX_CHARS and out["truncated"] is True


def test_without_keys_langfuse_is_simply_not_set_up(monkeypatch):
    langfuse.fetch_content.cache_clear()
    monkeypatch.setattr(langfuse, "credentials", lambda *a, **k: None)
    assert "not set up" in langfuse.fetch_content(TRACE, SPAN)["reason"]


def test_credentials_come_from_the_environment_then_the_private_file(tmp_path):
    f = tmp_path / "lf.env"
    f.write_text("LANGFUSE_HOST=http://file:3000/\nLANGFUSE_PUBLIC_KEY=pk-f\nLANGFUSE_SECRET_KEY=sk-f\n")
    f.chmod(0o600)
    assert langfuse.credentials(env={}, key_file=str(f)) == ("http://file:3000", "pk-f", "sk-f")
    assert langfuse.credentials(env={"LANGFUSE_HOST": "http://env:3000", "LANGFUSE_PUBLIC_KEY": "pk-e",
                                     "LANGFUSE_SECRET_KEY": "sk-e"}, key_file=str(f)) == ("http://env:3000", "pk-e", "sk-e")
    assert langfuse.credentials(env={}, key_file=str(tmp_path / "missing")) is None
