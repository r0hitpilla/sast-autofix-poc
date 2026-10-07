from fastapi.testclient import TestClient
from sqlalchemy import select

from dashboard import api
from dashboard.auth import hash_password
from dashboard.db import AuditEvent, User

from .conftest import NOW

CONTENT = {"severity_actions": {"Critical": "block", "High": "block", "Medium": "review", "Low": "allow"},
           "never_autofix": ["infra/**"], "repositories": ["o/*"], "branches": ["main", "SV"]}


def login(Session, name, role):
    with Session() as s:
        s.add(User(email=f"{name}@x.io", name=name, role=role,
                   password_hash=hash_password("a long enough password"), active=True, created_at=NOW))
        s.commit()
    c = TestClient(api.app)
    c.post("/api/auth/login", json={"name": name, "password": "a long enough password"})
    return c


def test_nothing_published_means_the_strict_default(client):
    data = client.get("/api/policy").json()
    assert data["active"] is None
    assert set(data["default"]["severity_actions"].values()) == {"block"}


def test_publishing_creates_numbered_immutable_versions_and_is_audited(client, Session):
    v1 = client.post("/api/policy", json={"content": CONTENT, "note": "first version"}).json()
    v2 = client.post("/api/policy", json={"content": {**CONTENT, "decisions_clear_blocks": True},
                                          "note": "let decisions clear blocks"}).json()
    assert (v1["version"], v2["version"]) == (1, 2)
    data = client.get("/api/policy").json()
    assert data["active"]["version"] == 2 and [v["version"] for v in data["versions"]] == [2, 1]
    with Session() as s:
        assert len(s.scalars(select(AuditEvent).where(AuditEvent.action == "policy_published")).all()) == 2


def test_invalid_policy_and_missing_note_are_refused(client):
    assert client.post("/api/policy", json={"content": {"severity_actions": {}}, "note": "bad"}).status_code == 422
    assert client.post("/api/policy", json={"content": CONTENT, "note": ""}).status_code == 422


def test_who_may_publish(client, Session):
    assert login(Session, "eng", "security_engineer").post(
        "/api/policy", json={"content": CONTENT, "note": "eng publishes"}).status_code == 200
    assert login(Session, "dev", "developer").post(
        "/api/policy", json={"content": CONTENT, "note": "dev tries"}).status_code == 403
    assert login(Session, "aud", "auditor").get("/api/policy").status_code == 200


def test_pipeline_gets_the_policy_only_where_its_scope_applies(client, monkeypatch):
    client.post("/api/policy", json={"content": CONTENT, "note": "scoped"})
    monkeypatch.setenv("SAST_HISTORY_TOKEN", "pipeline-secret")
    machine = TestClient(api.app, headers={"Authorization": "Bearer pipeline-secret"})
    inside = machine.get("/api/policy/active?repository=o/r&branch=SV").json()
    assert inside["applies"] and inside["policy"]["version"] == 1
    assert machine.get("/api/policy/active?repository=other/r&branch=SV").json()["applies"] is False
    assert machine.post("/api/policy", json={"content": CONTENT, "note": "machine"}).status_code == 401


def test_rules_list_comes_from_real_findings_with_the_policy_action(client):
    client.post("/api/policy", json={"content": CONTENT, "note": "for rules"})
    data = client.get("/api/rules").json()
    assert data["total"] > 0 and data["policy_version"] == 1
    by_sev = {r["severity"]: r["gate_action"] for r in data["items"]}
    assert by_sev.get("Low", "allow") == "allow" and by_sev.get("Critical", "block") == "block"
