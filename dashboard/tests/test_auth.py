from fastapi.testclient import TestClient
from sqlalchemy import select

from dashboard import api
from dashboard.auth import hash_password
from dashboard.db import AuditEvent, User

from .conftest import ADMIN_PASSWORD, NOW


def add_user(Session, email, role, password="a long enough password", active=True):
    with Session() as s:
        s.add(User(email=email, name=email.split("@")[0], role=role, password_hash=hash_password(password),
                   active=active, created_at=NOW))
        s.commit()


def signed_in(email, password="a long enough password"):
    c = TestClient(api.app)
    assert c.post("/api/auth/login", json={"name": email.split("@")[0], "password": password}).status_code == 200
    return c


def test_api_needs_a_signed_in_user(seeded, monkeypatch, tmp_path):
    anonymous = TestClient(api.app)
    assert anonymous.get("/api/findings").status_code == 401
    assert anonymous.get("/api/livez").status_code == 200  # monitoring stays public


def test_login_page_is_served_without_a_session(client):
    assert TestClient(api.app).get("/").status_code == 200


def test_wrong_password_and_unknown_email_get_the_same_answer(client, Session):
    add_user(Session, "dev@example.com", "developer")
    wrong = TestClient(api.app).post("/api/auth/login", json={"name": "dev", "password": "nope"})
    unknown = TestClient(api.app).post("/api/auth/login", json={"name": "who", "password": "nope"})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


def test_logout_revokes_the_session_at_once(client):
    assert client.get("/api/meta").status_code == 200
    assert client.post("/api/auth/logout", json={}).status_code == 200
    assert client.get("/api/meta").status_code == 401


def test_roles_decide_what_each_person_can_reach(client, Session):
    add_user(Session, "dev@example.com", "developer")
    add_user(Session, "audit@example.com", "auditor")
    developer, auditor = signed_in("dev@example.com"), signed_in("audit@example.com")

    assert developer.get("/api/findings").status_code == 200
    assert developer.get("/api/audit").status_code == 403
    assert developer.get("/api/users").status_code == 403

    assert auditor.get("/api/audit").status_code == 200
    assert auditor.get("/api/users").status_code == 403


def test_a_role_change_takes_effect_immediately(client, Session):
    add_user(Session, "dev@example.com", "developer")
    dev = signed_in("dev@example.com")
    assert dev.get("/api/audit").status_code == 403
    user_id = client.get("/api/users").json()["items"][0]["id"]
    dev_id = next(u["id"] for u in client.get("/api/users").json()["items"] if u["email"] == "dev@example.com")
    assert client.patch(f"/api/users/{dev_id}", json={"role": "auditor"}).status_code == 200
    # The old session was revoked, so the developer must sign in again.
    assert dev.get("/api/meta").status_code == 401
    assert signed_in("dev@example.com").get("/api/audit").status_code == 200
    assert user_id  # keeps the admin row referenced


def test_the_last_admin_cannot_be_demoted_or_disabled(client):
    admin_id = client.get("/api/auth/me").json()["id"]
    assert client.patch(f"/api/users/{admin_id}", json={"role": "developer"}).status_code == 409
    assert client.patch(f"/api/users/{admin_id}", json={"active": False}).status_code == 409


def test_disabled_users_cannot_sign_in(client, Session):
    add_user(Session, "gone@example.com", "developer", active=False)
    r = TestClient(api.app).post("/api/auth/login", json={"name": "gone",
                                                          "password": "a long enough password"})
    assert r.status_code == 401


def test_changes_that_write_data_must_be_json(client):
    r = client.post("/api/auth/login", data={"name": "admin", "password": ADMIN_PASSWORD})
    assert r.status_code == 415


def test_repeated_failures_lock_the_account(client, Session):
    add_user(Session, "dev@example.com", "developer")
    attacker = TestClient(api.app)
    for _ in range(5):
        attacker.post("/api/auth/login", json={"name": "dev", "password": "wrong"})
    locked = attacker.post("/api/auth/login", json={"name": "dev",
                                                    "password": "a long enough password"})
    assert locked.status_code == 429


def test_short_passwords_are_refused(client):
    r = client.post("/api/users", json={"name": "New Person", "email": "new@example.com", "role": "developer", "password": "short"})
    assert r.status_code == 422


def test_the_audit_trail_records_sign_ins_and_user_changes(client, Session):
    client.post("/api/users", json={"name": "New Person", "email": "new@example.com", "role": "developer",
                                    "password": "a long enough password"})
    TestClient(api.app).post("/api/auth/login", json={"name": "New Person", "password": "wrong"})
    with Session() as s:
        actions = {e.action for e in s.scalars(select(AuditEvent)).all()}
    assert {"login", "user_created", "login_failed"} <= actions


def test_pipeline_can_read_history_with_its_machine_token(client, monkeypatch):
    monkeypatch.setenv("SAST_HISTORY_TOKEN", "pipeline-secret")
    anonymous = TestClient(api.app)
    assert anonymous.get("/api/history?repository=o/r").status_code == 401
    ok = anonymous.get("/api/history?repository=o/r", headers={"Authorization": "Bearer pipeline-secret"})
    assert ok.status_code == 200
    bad = anonymous.get("/api/history?repository=o/r", headers={"Authorization": "Bearer guess"})
    assert bad.status_code == 401


def test_machine_token_does_not_open_other_areas(client, monkeypatch):
    monkeypatch.setenv("SAST_HISTORY_TOKEN", "pipeline-secret")
    r = TestClient(api.app).get("/api/users", headers={"Authorization": "Bearer pipeline-secret"})
    assert r.status_code == 401
