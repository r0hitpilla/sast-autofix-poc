from fastapi.testclient import TestClient
from sqlalchemy import select

from dashboard import api
from dashboard.auth import hash_password
from dashboard.db import AuditEvent, TrackedFinding, User
from dashboard.ingest import ingest

from .conftest import NOW, finding, report

FP = "a" * 64  # decisions take a full fingerprint, as the pipeline writes them


def add_user(Session, name, role):
    with Session() as s:
        s.add(User(email=f"{name}@example.com", name=name, role=role,
                   password_hash=hash_password("a long enough password"), active=True, created_at=NOW))
        s.commit()


def signed_in(name):
    c = TestClient(api.app)
    assert c.post("/api/auth/login", json={"name": name, "password": "a long enough password"}).status_code == 200
    return c


def seed(Session):
    ingest(report("d1", findings=[finding(FP, 5, "CWE-79: x", "High", "fix", "fixed and validated", True, 1)]), Session)


def test_security_engineer_marks_a_false_positive_with_a_reason(client, Session):
    seed(Session)
    add_user(Session, "eng", "security_engineer")
    r = signed_in("eng").post(f"/api/findings/{FP}/decision",
                              json={"decision": "false_positive", "reason": "only reachable from tests"})
    assert r.status_code == 200
    assert r.json()["decision"] == "false_positive"
    with Session() as s:
        t = s.get(TrackedFinding, FP)
        assert t.decision == "false_positive" and t.decided_by == "eng@example.com"


def test_the_decision_is_audited_with_its_reason(client, Session):
    seed(Session)
    client.post(f"/api/findings/{FP}/decision", json={"decision": "suppressed", "reason": "accepted risk for Q4"})
    with Session() as s:
        event = s.scalar(select(AuditEvent).where(AuditEvent.action == "finding_decision"))
    assert event.detail["to"] == "suppressed" and event.detail["reason"] == "accepted risk for Q4"


def test_developers_and_auditors_cannot_decide(client, Session):
    seed(Session)
    add_user(Session, "dev", "developer")
    add_user(Session, "audit", "auditor")
    body = {"decision": "false_positive", "reason": "no"}
    assert signed_in("dev").post(f"/api/findings/{FP}/decision", json=body).status_code == 403
    assert signed_in("audit").post(f"/api/findings/{FP}/decision", json=body).status_code == 403


def test_a_reason_is_required(client, Session):
    seed(Session)
    assert client.post(f"/api/findings/{FP}/decision", json={"decision": "false_positive", "reason": "x"}).status_code == 422


def test_reopening_clears_the_decision(client, Session):
    seed(Session)
    client.post(f"/api/findings/{FP}/decision", json={"decision": "false_positive", "reason": "tests only"})
    assert client.post(f"/api/findings/{FP}/decision", json={"decision": "open"}).status_code == 200
    with Session() as s:
        assert s.get(TrackedFinding, FP).decision is None


def test_unknown_or_malformed_findings_are_refused(client, Session):
    seed(Session)
    assert client.post(f"/api/findings/{'b' * 64}/decision", json={"decision": "suppressed", "reason": "abc"}).status_code == 404
    assert client.post("/api/findings/not-a-fingerprint/decision", json={"decision": "suppressed", "reason": "abc"}).status_code == 422


def test_a_decision_survives_a_new_scan_of_the_same_finding(client, Session):
    seed(Session)
    client.post(f"/api/findings/{FP}/decision", json={"decision": "false_positive", "reason": "tests only"})
    ingest(report("d2", hours_ago=0, findings=[finding(FP, 9, "CWE-79: x", "High", "fix", "fixed and validated", True, 1)]), Session)
    with Session() as s:
        t = s.get(TrackedFinding, FP)
        assert t.decision == "false_positive" and t.occurrences == 2
