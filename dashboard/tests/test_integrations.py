import json

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import select

from dashboard import api, integrations
from dashboard.auth import hash_password
from dashboard.db import AuditEvent, Integration, OutboxMessage, TrackedFinding, User
from dashboard.ingest import ingest

from .conftest import NOW, finding, report

SLACK = "https://hooks.slack.example/services/T/B/x"


@pytest.fixture
def outside(monkeypatch):
    """Stands in for every outside system; records what was sent."""
    monkeypatch.setenv("SAST_SECRET_KEY", Fernet.generate_key().decode())
    calls, behaviour = [], {"status": 200}

    def handler(request: httpx.Request):
        calls.append(request)
        if "api.github.com/user" in str(request.url):
            return httpx.Response(behaviour["status"], json={"login": "octo"})
        if "/rest/api/3/issue" in str(request.url):
            return httpx.Response(201, json={"key": "SEC-1"})
        if "/rest/api/3/project/" in str(request.url):
            return httpx.Response(200, json={"key": "SEC", "name": "Security"})
        return httpx.Response(behaviour["status"], json={})

    monkeypatch.setattr(integrations, "client",
                        lambda: httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False))
    return calls, behaviour


def connect_slack(client, events=("gate_blocked",)):
    return client.post("/api/integrations", json={"provider": "slack", "values": {"webhook_url": SLACK},
                                                  "events": list(events)})


def test_catalogue_shows_every_provider_and_marks_missing_connectors(client, outside):
    data = client.get("/api/integrations").json()
    by_key = {i["key"]: i for c in data["categories"] for i in c["items"]}
    assert [c["category"] for c in data["categories"]] == ["Source control", "CI/CD", "Notifications", "Ticketing", "Security"]
    assert by_key["gitlab"]["status"] == "unavailable"
    assert by_key["slack"]["status"] == "not_configured"


def test_saving_tests_the_connection_and_never_returns_the_secret(client, outside, Session):
    calls, _ = outside
    r = connect_slack(client)
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "connected" and body["secrets_set"] == ["webhook_url"]
    assert SLACK not in json.dumps(body)
    assert len(calls) == 1  # the test message
    with Session() as s:
        stored = s.scalar(select(Integration))
        assert SLACK not in stored.secret_enc  # encrypted at rest


def test_a_failing_connection_is_saved_as_failing(client, outside):
    outside[1]["status"] = 403
    assert connect_slack(client).json()["status"] == "failing"


def test_webhook_urls_must_be_https(client, outside):
    r = client.post("/api/integrations", json={"provider": "slack", "values": {"webhook_url": "http://x/y"}})
    assert r.status_code == 422


def test_unavailable_providers_cannot_be_configured(client, outside):
    assert client.post("/api/integrations", json={"provider": "gitlab", "values": {}}).status_code == 422


def test_only_admins_manage_and_developers_cannot_see(client, outside, Session):
    with Session() as s:
        for name, role in (("eng", "security_engineer"), ("dev", "developer")):
            s.add(User(email=f"{name}@x.io", name=name, role=role,
                       password_hash=hash_password("a long enough password"), active=True, created_at=NOW))
        s.commit()

    def login(name):
        c = TestClient(api.app)
        c.post("/api/auth/login", json={"name": name, "password": "a long enough password"})
        return c

    eng, dev = login("eng"), login("dev")
    assert eng.get("/api/integrations").status_code == 200
    assert connect_slack(eng).status_code == 403
    assert dev.get("/api/integrations").status_code == 403


def test_a_blocked_gate_is_queued_once_and_delivered(client, outside, Session):
    calls, _ = outside
    connect_slack(client)
    calls.clear()
    r = report("n1", findings=[finding("a" * 64, 5, "CWE-79: x", "High", "fix", "fix failed", False, 2)])
    ingest(r, Session)
    ingest(r, Session)  # a CI retry must not notify twice
    with Session() as s:
        assert s.scalar(select(OutboxMessage).where(OutboxMessage.event == "gate_blocked")) is not None
        assert len(s.scalars(select(OutboxMessage)).all()) == 1
        assert integrations.deliver_pending(s) == 1
    assert len(calls) == 1 and "Merge gate blocked" in json.loads(calls[0].content)["text"]


def test_failed_deliveries_back_off_and_are_kept(client, outside, Session):
    calls, behaviour = outside
    connect_slack(client)
    behaviour["status"] = 500
    ingest(report("n2", findings=[finding("b" * 64, 5, "CWE-79: x", "High", "fix", "fix failed", False, 2)]), Session)
    with Session() as s:
        assert integrations.deliver_pending(s) == 0
        msg = s.scalar(select(OutboxMessage))
        assert msg.attempts == 1 and msg.delivered_at is None and msg.last_error


def test_dry_runs_notify_nobody(client, outside, Session):
    connect_slack(client, events=["run_completed", "gate_blocked"])
    ingest(report("n3", dry_run=True), Session)
    with Session() as s:
        assert s.scalars(select(OutboxMessage)).all() == []


def test_jira_issue_is_created_once_per_finding(client, outside, Session):
    client.post("/api/integrations", json={"provider": "jira", "values": {
        "base_url": "https://acme.atlassian.example", "email": "a@x.io", "api_token": "t", "project_key": "SEC"}})
    fp = "c" * 64
    ingest(report("n4", findings=[finding(fp, 5, "CWE-79: x", "High", "fix", "fix failed", False, 2)]), Session)
    first = client.post(f"/api/findings/{fp}/issue", json={})
    again = client.post(f"/api/findings/{fp}/issue", json={})
    assert first.json()["issue_key"] == again.json()["issue_key"] == "SEC-1"
    assert sum(1 for c in outside[0] if "/rest/api/3/issue" in str(c.url)) == 1
    with Session() as s:
        assert s.get(TrackedFinding, fp).issue_url.endswith("/browse/SEC-1")
        assert s.scalar(select(AuditEvent).where(AuditEvent.action == "issue_created")) is not None


def test_without_a_secret_key_nothing_is_saved(client, outside, monkeypatch):
    monkeypatch.delenv("SAST_SECRET_KEY")
    assert connect_slack(client).status_code == 503
