"""FastAPI app: JSON API under /api, the built React app everywhere else.

Phase 1 is read-only and has no sign-in, so it must only listen on
127.0.0.1 (see README "Dashboard"). Run:

    dashboard/.venv/bin/uvicorn dashboard.api:app --host 127.0.0.1 --port 8710
"""

import asyncio
import csv
import io
import os
import re
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import Depends, FastAPI, HTTPException, Path, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select, text
from sqlalchemy.orm import Session

import policy as policy_mod

from . import integrations, queries
from .auth import (COOKIE, MIN_PASSWORD_LENGTH, ROLE_LABELS, ROLES, SESSION_TTL, authorize,
                   burn_password_time, client_ip, hash_password, lockout_active, now,
                   permissions_for, record, revoke_user_sessions, start_session, token_hash,
                   verify_password)
from .db import (AuditEvent, AuthSession, FindingRow, Integration, LlmCall, OutboxMessage, PolicyVersion, Run,
                 TrackedFinding, User,
                 make_sessionmaker)
from .deps import get_session
from .settings import Settings, get_settings
from .sources import github, langfuse, ollama, system

VERSION = "1.1.0"

DELIVERY_INTERVAL = 15  # seconds between outbox sweeps


def _deliver_once() -> None:
    try:
        with make_sessionmaker()() as session:
            integrations.deliver_pending(session)
    except Exception as exc:  # a delivery problem must never stop the dashboard
        print(f"[outbox] delivery sweep failed: {exc}", flush=True)


@asynccontextmanager
async def lifespan(_app):
    """Deliver queued notifications in the background while the service runs."""
    task = None
    if os.environ.get("SAST_DELIVERY", "on") != "off":
        async def loop():
            while True:
                await asyncio.to_thread(_deliver_once)
                await asyncio.sleep(DELIVERY_INTERVAL)
        task = asyncio.create_task(loop())
    yield
    if task:
        task.cancel()


app = FastAPI(title="SAST Autofix dashboard", version=VERSION, docs_url="/api/docs",
              openapi_url="/api/openapi.json", redoc_url=None, lifespan=lifespan,
              # Every request passes the sign-in and role check; see auth.py.
              dependencies=[Depends(authorize)])


@app.middleware("http")
async def require_json_for_changes(request: Request, call_next):
    """Cross-site forms can't send JSON without a preflight, so requiring JSON
    for every change under /api/ blocks CSRF. Runs before routing, so it also
    covers requests whose bodies would otherwise fail validation first."""
    if (request.url.path.startswith("/api/") and request.method not in ("GET", "HEAD", "OPTIONS")
            and "application/json" not in request.headers.get("content-type", "")):
        return JSONResponse({"detail": "requests that change data must be JSON"}, status_code=415)
    return await call_next(request)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    if not request.url.path.startswith("/api/docs"):
        resp.headers.setdefault(
            "Content-Security-Policy",
            # Fonts are bundled (ui/web, @fontsource): no third-party origins at all.
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
            "form-action 'self'",
        )
    return resp


def _since(days: int | None) -> datetime | None:
    return datetime.now(timezone.utc) - timedelta(days=days) if days else None


Repo = Query(None, max_length=200, description="owner/name; omit for all repositories")


# ---- API -------------------------------------------------------------------

@app.get("/api/meta")
def meta(session: Session = Depends(get_session)):
    return {"version": VERSION, "repositories": queries.repositories(session)}


@app.get("/api/overview")
def overview(repository: str | None = Repo, days: int = Query(7, ge=1, le=365),
             session: Session = Depends(get_session)):
    return queries.overview(session, repository, days)


@app.get("/api/runs")
def runs(repository: str | None = Repo, days: int | None = Query(None, ge=1, le=365),
         limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
         session: Session = Depends(get_session)):
    return queries.list_runs(session, repository, _since(days), limit, offset)


@app.get("/api/runs/{run_id}")
def run(run_id: str, session: Session = Depends(get_session)):
    detail = queries.run_detail(session, run_id)
    if detail is None:
        raise HTTPException(404, "run not found")
    return detail


@app.get("/api/history")
def history(repository: str = Query(..., max_length=200), session: Session = Depends(get_session)):
    return {"items": queries.history_for(session, repository)}


@app.get("/api/findings")
def findings(state: str = Query("open", pattern="^(open|all)$"), repository: str | None = Repo,
             severity: str | None = Query(None, pattern="^(Critical|High|Medium|Low)$"),
             route: str | None = Query(None, pattern="^(fix|review|reject)$"),
             days: int | None = Query(None, ge=1, le=365),
             limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
             session: Session = Depends(get_session)):
    return queries.list_findings(session, state, repository, severity, route, _since(days), limit, offset)


@app.get("/api/findings/{finding_id}")
def finding(finding_id: int, session: Session = Depends(get_session)):
    detail = queries.finding_detail(session, finding_id)
    if detail is None:
        raise HTTPException(404, "finding not found")
    return detail


@app.get("/api/prs")
def prs(repository: str | None = Repo, session: Session = Depends(get_session)):
    return {"items": queries.list_prs(session, repository)}


@app.get("/api/prs/{owner}/{name}/{number}")
def pr(owner: str, name: str, number: int, live: bool = True,
       session: Session = Depends(get_session)):
    repository = f"{owner}/{name}"
    detail = queries.pr_detail(session, repository, number)
    if detail is None:
        raise HTTPException(404, "pull request not found")
    detail["live"] = github.pr_state(repository, number) if live else {"available": False}
    return detail


@app.get("/api/runs/{run_id}/ai")
def run_ai(run_id: str, user: User = Depends(authorize), session: Session = Depends(get_session)):
    """The run's AI calls as a timeline, and where to find its trace in Langfuse."""
    if session.get(Run, run_id) is None:
        raise HTTPException(404, "no such run")
    calls = queries.run_calls(session, run_id)
    creds = langfuse.credentials()
    trace_id = next((c["trace_id"] for c in calls if c["trace_id"]), None)
    can_read = "ai:content" in permissions_for(user.role)
    for c in calls:
        c["link"] = langfuse.trace_url(c["trace_id"], c["span_id"], creds) if c["traced"] else None
        c.pop("trace_id"), c.pop("span_id")
    return {"calls": calls, "langfuse": {"connected": creds is not None, "trace_url": langfuse.trace_url(trace_id, None, creds),
                                          "can_read_content": can_read}}


@app.get("/api/ai-calls/{call_id}/content")
def ai_call_content(call_id: int, request: Request, response: Response, actor: User = Depends(authorize),
                    session: Session = Depends(get_session)):
    """The prompt and reply of one AI call, read from Langfuse. They contain the
    client's source code, so this needs the ai:content permission and every
    view is written to the audit log."""
    call = session.get(LlmCall, call_id)
    if call is None:
        raise HTTPException(404, "no such call")
    if not (call.trace_id and call.span_id):
        return {"available": False, "reason": "This call was not traced to Langfuse."}
    record(session, "ai_content_viewed", actor=actor, target=f"run {call.run_id} · {call.purpose} · {call.ref or 'n/a'}",
           detail={"call": call_id}, ip=client_ip(request))
    session.commit()
    response.headers["Cache-Control"] = "no-store"
    return langfuse.fetch_content(call.trace_id, call.span_id)


@app.get("/api/usage")
def usage(repository: str | None = Repo, days: int = Query(30, ge=1, le=365),
          session: Session = Depends(get_session)):
    """AI usage (tokens, calls, time) over the window, by model, purpose and day."""
    return queries.usage_overview(session, repository, _since(days))


@app.get("/api/models")
def models(session: Session = Depends(get_session)):
    latest = queries.list_runs(session, limit=1)["items"]
    run = queries.run_detail(session, latest[0]["id"]) if latest else None
    return {"ollama": ollama.status(), "provenance": run["provenance"] if run else None}


@app.get("/api/health")
def health(settings: Settings = Depends(get_settings), session: Session = Depends(get_session)):
    try:
        session.execute(text("select 1"))
        db_ok = True
    except Exception:  # noqa: BLE001 - any DB failure is "down" on a health page
        db_ok = False
    snap = system.snapshot(settings.runner_service)
    snap["services"]["database"] = {"ok": db_ok}
    snap["services"]["ollama"] = {"ok": ollama.status()["online"]}
    since = datetime.now(timezone.utc) - timedelta(days=1)
    day = queries.list_runs(session, since=since, limit=200)["items"] if db_ok else []
    snap["runs_24h"] = len(day)
    snap["blocked_24h"] = sum(1 for r in day if r["status"] == "Blocked")
    return snap


@app.get("/api/livez")
def livez():
    return {"ok": True}


@app.get("/api/reports")
def reports(repository: str | None = Repo, days: int = Query(30, ge=1, le=365),
            session: Session = Depends(get_session)):
    return queries.report(session, repository, days)


@app.get("/api/reports/export.{fmt}")
def export(fmt: str, repository: str | None = Repo, days: int = Query(30, ge=1, le=365),
           session: Session = Depends(get_session)):
    rows = queries.export_rows(session, repository, days)
    name = f"sast-autofix-findings-{days}d"
    if fmt == "json":
        return JSONResponse(rows, headers={"Content-Disposition": f'attachment; filename="{name}.json"'})
    if fmt == "csv":
        buf = io.StringIO()
        fields = list(rows[0]) if rows else ["run_id"]
        writer = csv.DictWriter(buf, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            # neutralise spreadsheet formula injection from scanned content
            writer.writerow({k: ("'" + v if isinstance(v, str) and v[:1] in "=+-@" else v)
                             for k, v in row.items()})
        return Response(buf.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="{name}.csv"'})
    raise HTTPException(404, "unknown export format")


# ---- sign-in, users and audit ----------------------------------------------

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class LoginIn(BaseModel):
    name: str = Field(max_length=120)
    password: str = Field(max_length=1024)


class UserIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: str = Field(max_length=254)
    role: str = Field(max_length=32)
    password: str = Field(max_length=1024)


class UserPatch(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=120)
    role: str | None = Field(default=None, max_length=32)
    active: bool | None = None
    password: str | None = Field(default=None, max_length=1024)


def _me(user: User) -> dict:
    return {"id": user.id, "email": user.email, "name": user.name, "role": user.role,
            "role_label": ROLE_LABELS.get(user.role, user.role),
            "permissions": sorted(permissions_for(user.role))}


def _user_json(user: User) -> dict:
    return {**_me(user), "active": user.active, "created_at": queries.iso(user.created_at),
            "last_login_at": queries.iso(user.last_login_at)}


def _check_role(role: str) -> None:
    if role not in ROLES:
        raise HTTPException(422, f"role must be one of: {', '.join(ROLES)}")


def _check_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(422, f"password must be at least {MIN_PASSWORD_LENGTH} characters")


def _by_name(session: Session, name: str) -> User | None:
    return session.scalar(select(User).where(func.lower(User.name) == name.strip().lower()))


@app.post("/api/auth/login")
def login(body: LoginIn, request: Request, response: Response, session: Session = Depends(get_session)):
    name = body.name.strip().lower()
    if lockout_active(session, name):
        record(session, "login_failed", "failure", actor_email=None, target=name,
               detail={"reason": "locked"}, ip=client_ip(request))
        session.commit()
        raise HTTPException(429, "Too many failed sign-in attempts. Try again in 15 minutes.")
    user = _by_name(session, body.name)
    if user is None:
        burn_password_time()
        ok = False
    else:
        ok = user.active and verify_password(body.password, user.password_hash)
    if not ok:
        record(session, "login_failed", "failure", target=name, ip=client_ip(request))
        session.commit()
        raise HTTPException(401, "Name or password is incorrect.")
    token = start_session(session, user, request)
    user.last_login_at = now()
    record(session, "login", actor=user, ip=client_ip(request))
    session.commit()
    response.set_cookie(COOKIE, token, max_age=int(SESSION_TTL.total_seconds()), httponly=True,
                        samesite="strict", secure=request.url.scheme == "https", path="/")
    return _me(user)


@app.post("/api/auth/logout")
def logout(request: Request, response: Response, user: User = Depends(authorize),
           session: Session = Depends(get_session)):
    token = request.cookies.get(COOKIE)
    if token:
        session.execute(delete(AuthSession).where(AuthSession.token_hash == token_hash(token)))
    record(session, "logout", actor=user, ip=client_ip(request))
    session.commit()
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@app.get("/api/auth/me")
def me(user: User = Depends(authorize)):
    return _me(user)


@app.get("/api/users")
def users(session: Session = Depends(get_session)):
    rows = session.scalars(select(User).order_by(User.email)).all()
    return {"items": [_user_json(u) for u in rows]}


@app.post("/api/users")
def create_user(body: UserIn, request: Request, actor: User = Depends(authorize),
                session: Session = Depends(get_session)):
    email = body.email.strip().lower()
    name = body.name.strip()
    if not EMAIL_RE.match(email):
        raise HTTPException(422, "enter a valid email address")
    _check_role(body.role)
    _check_password(body.password)
    if _by_name(session, name):
        raise HTTPException(409, "a user with that name already exists")
    if session.scalar(select(User.id).where(User.email == email)):
        raise HTTPException(409, "a user with that email already exists")
    user = User(email=email, name=name, role=body.role,
                password_hash=hash_password(body.password), active=True, created_at=now())
    session.add(user)
    session.flush()
    record(session, "user_created", actor=actor, target=email, detail={"role": body.role},
           ip=client_ip(request))
    session.commit()
    return _user_json(user)


@app.patch("/api/users/{user_id}")
def update_user(user_id: int, body: UserPatch, request: Request, actor: User = Depends(authorize),
                session: Session = Depends(get_session)):
    user = session.get(User, user_id)
    if user is None:
        raise HTTPException(404, "no such user")
    changes = {}
    if body.name is not None and body.name.strip() != user.name:
        clash = _by_name(session, body.name)
        if clash is not None and clash.id != user.id:
            raise HTTPException(409, "a user with that name already exists")
        changes["name"] = {"from": user.name, "to": body.name.strip()}
        user.name = body.name.strip()
    if body.role is not None and body.role != user.role:
        _check_role(body.role)
        changes["role"] = {"from": user.role, "to": body.role}
        user.role = body.role
    if body.active is not None and body.active != user.active:
        changes["active"] = {"from": user.active, "to": body.active}
        user.active = body.active
    if body.password is not None:
        _check_password(body.password)
        user.password_hash = hash_password(body.password)
        changes["password"] = "changed"
    # The product must always have someone who can manage users.
    active_admins = session.scalar(select(func.count(User.id)).where(User.role == "admin", User.active.is_(True)))
    if active_admins == 0:
        raise HTTPException(409, "at least one active admin is needed")
    if changes.get("role") or changes.get("active") or "password" in changes:
        revoke_user_sessions(session, user.id)  # takes effect at once, not at next sign-in
    record(session, "user_updated", actor=actor, target=user.email, detail=changes, ip=client_ip(request))
    session.commit()
    return _user_json(user)


class DecisionIn(BaseModel):
    decision: str = Field(max_length=16)          # false_positive | suppressed | open (reopen)
    reason: str = Field(default="", max_length=500)


DECISIONS = {"false_positive", "suppressed", "open"}


@app.post("/api/findings/{fingerprint}/decision")
def decide(body: DecisionIn, request: Request, fingerprint: str = Path(pattern=r"^[0-9a-f]{64}$"),
           actor: User = Depends(authorize), session: Session = Depends(get_session)):
    """Record a person's decision about a finding. Every decision is audited
    with its reason; reopening keeps the history in the audit log."""
    tracked = session.get(TrackedFinding, fingerprint)
    if tracked is None:
        raise HTTPException(404, "no such finding")
    if body.decision not in DECISIONS:
        raise HTTPException(422, f"decision must be one of: {', '.join(sorted(DECISIONS))}")
    reason = body.reason.strip()
    reopening = body.decision == "open"
    if not reopening and len(reason) < 3:
        raise HTTPException(422, "say why, in a few words, so the audit log makes sense")
    before = tracked.decision
    tracked.decision = None if reopening else body.decision
    tracked.decision_reason = None if reopening else reason
    tracked.decided_by = None if reopening else actor.email
    tracked.decided_at = None if reopening else now()
    record(session, "finding_decision", actor=actor,
           target=f"{tracked.repository} {tracked.rule_id} {tracked.file}",
           detail={"from": before, "to": tracked.decision, "reason": reason}, ip=client_ip(request))
    session.commit()
    return {"decision": tracked.decision, "decision_reason": tracked.decision_reason,
            "decided_by": tracked.decided_by, "decided_at": queries.iso(tracked.decided_at)}


# ---- integrations ----------------------------------------------------------

class IntegrationIn(BaseModel):
    provider: str = Field(max_length=32)
    values: dict[str, str] = Field(default_factory=dict)
    events: list[str] = Field(default_factory=list)


class IntegrationPatch(BaseModel):
    enabled: bool


def _builtin_meta(session: Session, key: str) -> tuple[str, str]:
    if key == "github_actions":
        runs = session.scalars(select(Run).where(Run.dry_run.is_(False), Run.url.like("%/actions/runs/%"))
                               .order_by(Run.started_at.desc())).all()
        if not runs:
            return "untested", "No runs recorded from GitHub Actions yet"
        return "connected", f"Runs recorded {len(runs)}\nLast run {queries.iso(runs[0].started_at)[:16].replace('T', ' ')}"
    if key == "dependency_scanners":
        n = session.scalar(select(func.count(FindingRow.id)).where(
            FindingRow.rule_id.like("osv.%") | FindingRow.rule_id.like("gitleaks.%"))) or 0
        return "connected", f"osv-scanner and gitleaks, in the pipeline\nFindings recorded {n}"
    return "untested", ""


def _integration_json(spec: dict, row: Integration | None, session: Session) -> dict:
    out = {"key": spec["key"], "name": spec["name"], "available": spec.get("available", False),
           "builtin": spec.get("builtin", False), "auth": spec.get("auth"),
           "permissions": spec.get("permissions", []),
           "fields": [{"key": k, "label": l, "secret": s, "required": r} for k, l, s, r in spec.get("fields", [])],
           "events": [{"key": e, "label": integrations.EVENTS[e]} for e in spec.get("events", [])]}
    if spec.get("builtin"):
        status, meta = _builtin_meta(session, spec["key"])
        return {**out, "status": status, "meta": meta, "configured": True}
    if row is None:
        return {**out, "status": "not_configured" if spec.get("available") else "unavailable",
                "meta": "" if spec.get("available") else "Connector not available yet", "configured": False}
    try:
        secrets = integrations.decrypt(row.secret_enc)
    except integrations.IntegrationError:
        secrets = {}
    return {**out, "configured": True, "id": row.id, "enabled": row.enabled,
            "status": row.status if row.enabled else "disabled",
            "config": row.config, "secrets_set": sorted(k for k, v in secrets.items() if v),
            "subscribed": row.events, "last_test_at": queries.iso(row.last_test_at),
            "last_test_detail": row.last_test_detail, "last_event_at": queries.iso(row.last_event_at),
            "last_error": row.last_error,
            "meta": (f"Last event {queries.iso(row.last_event_at)[:16].replace('T', ' ')}" if row.last_event_at
                     else "No events delivered yet")}


@app.get("/api/integrations")
def list_integrations(session: Session = Depends(get_session)):
    rows = {r.provider: r for r in session.scalars(select(Integration)).all()}
    pending = session.scalar(select(func.count(OutboxMessage.id)).where(OutboxMessage.delivered_at.is_(None))) or 0
    return {"categories": [{"category": cat, "items": [_integration_json(spec, rows.get(spec["key"]), session)
                                                      for spec in items]}
                           for cat, items in integrations.CATALOGUE],
            "events": integrations.EVENTS, "outbox_pending": pending,
            "secrets_ready": bool(get_settings().secret_key)}


def _settings_for(body: IntegrationIn, session: Session) -> tuple[Integration | None, dict, dict, list]:
    existing = session.scalar(select(Integration).where(Integration.provider == body.provider))
    try:
        old_secrets = integrations.decrypt(existing.secret_enc) if existing else {}
        config, secrets = integrations.split_settings(body.provider, body.values, old_secrets)
        events = integrations.valid_events(body.provider, body.events)
    except integrations.IntegrationError as exc:
        raise HTTPException(422, str(exc)) from exc
    return existing, config, secrets, events


@app.post("/api/integrations/test")
def test_integration(body: IntegrationIn, request: Request, actor: User = Depends(authorize),
                     session: Session = Depends(get_session)):
    """The wizard's "Test connection" step: test the values as entered, before saving."""
    existing, config, secrets, _ = _settings_for(body, session)
    results = integrations.test_connection(body.provider, config, secrets)
    ok = all(r["ok"] for r in results)
    if existing is not None:
        existing.status = "connected" if ok else "failing"
        existing.last_test_at, existing.last_test_detail = now(), results
    record(session, "integration_tested", "success" if ok else "failure", actor=actor,
           target=body.provider, detail={"checks": results}, ip=client_ip(request))
    session.commit()
    return {"ok": ok, "results": results}


@app.post("/api/integrations")
def save_integration(body: IntegrationIn, request: Request, actor: User = Depends(authorize),
                     session: Session = Depends(get_session)):
    """Create or update a provider's connection, then test it so the status is real."""
    existing, config, secrets, events = _settings_for(body, session)
    try:
        secret_enc = integrations.encrypt(secrets)
    except integrations.IntegrationError as exc:
        raise HTTPException(503, str(exc)) from exc
    results = integrations.test_connection(body.provider, config, secrets)
    ok = all(r["ok"] for r in results)
    row = existing or Integration(provider=body.provider, created_by=actor.email, created_at=now(), enabled=True)
    row.config, row.secret_enc, row.events = config, secret_enc, events
    row.status, row.last_test_at, row.last_test_detail = ("connected" if ok else "failing"), now(), results
    row.updated_at = now()
    session.add(row)
    record(session, "integration_updated" if existing else "integration_created", actor=actor,
           target=body.provider, detail={"events": events, "settings": sorted(config), "secrets": sorted(secrets),
                                         "test_ok": ok}, ip=client_ip(request))
    session.commit()
    spec = integrations.PROVIDERS[body.provider]
    return _integration_json(spec, row, session)


@app.patch("/api/integrations/{provider}")
def toggle_integration(provider: str, body: IntegrationPatch, request: Request, actor: User = Depends(authorize),
                       session: Session = Depends(get_session)):
    row = session.scalar(select(Integration).where(Integration.provider == provider))
    if row is None:
        raise HTTPException(404, "not configured")
    row.enabled, row.updated_at = body.enabled, now()
    record(session, "integration_enabled" if body.enabled else "integration_disabled", actor=actor,
           target=provider, ip=client_ip(request))
    session.commit()
    return _integration_json(integrations.PROVIDERS[provider], row, session)


@app.delete("/api/integrations/{provider}")
def delete_integration(provider: str, request: Request, actor: User = Depends(authorize),
                       session: Session = Depends(get_session)):
    row = session.scalar(select(Integration).where(Integration.provider == provider))
    if row is None:
        raise HTTPException(404, "not configured")
    session.delete(row)
    record(session, "integration_deleted", actor=actor, target=provider, ip=client_ip(request))
    session.commit()
    return {"ok": True}


@app.post("/api/findings/{fingerprint}/issue")
def create_issue(request: Request, fingerprint: str = Path(pattern=r"^[0-9a-f]{64}$"),
                 actor: User = Depends(authorize), session: Session = Depends(get_session)):
    """Open a Jira issue for a finding (once; later calls return the same issue)."""
    tracked = session.get(TrackedFinding, fingerprint)
    if tracked is None:
        raise HTTPException(404, "no such finding")
    if tracked.issue_key:
        return {"issue_key": tracked.issue_key, "issue_url": tracked.issue_url}
    jira = session.scalar(select(Integration).where(Integration.provider == "jira", Integration.enabled.is_(True)))
    if jira is None:
        raise HTTPException(409, "Jira is not connected. An admin can connect it under Integrations.")
    link = f"{get_settings().public_url.rstrip('/')}/findings"
    summary = f"[SAST] {queries.cwe_title(tracked.cwe)} in {tracked.file} ({tracked.repository})"
    description = (f"Rule: {tracked.rule_id}\nCWE: {tracked.cwe}\nSeverity: {tracked.severity}\n"
                   f"File: {tracked.file}\nSeen in {tracked.occurrences} run(s), last {queries.iso(tracked.last_seen)}\n"
                   f"Status: {tracked.disposition}\nDashboard: {link}")
    try:
        key, url = integrations.create_jira_issue(jira, summary, description)
    except (integrations.IntegrationError, httpx.HTTPError) as exc:
        record(session, "issue_create_failed", "failure", actor=actor, target=fingerprint,
               detail={"error": str(exc)}, ip=client_ip(request))
        session.commit()
        raise HTTPException(502, f"Jira: {exc}") from exc
    tracked.issue_key, tracked.issue_url = key, url
    record(session, "issue_created", actor=actor, target=fingerprint, detail={"issue": key}, ip=client_ip(request))
    session.commit()
    return {"issue_key": key, "issue_url": url}


# ---- security policy and rules ---------------------------------------------

POLICY_NAME = "Production Security Policy"


class PolicyIn(BaseModel):
    content: dict
    note: str = Field(min_length=3, max_length=300)


def _version_json(v: PolicyVersion) -> dict:
    return {"version": v.version, "content": v.content, "note": v.note,
            "published_by": v.published_by, "published_at": queries.iso(v.published_at)}


@app.get("/api/policy")
def get_policy(session: Session = Depends(get_session)):
    versions = session.scalars(select(PolicyVersion).order_by(PolicyVersion.version.desc())).all()
    active = versions[0] if versions else None
    return {"name": POLICY_NAME,
            "active": _version_json(active) if active else None,
            # What applies while nothing is published: the pipeline's strict default.
            "default": policy_mod.STRICT.to_dict(),
            "always_never_autofix": list(policy_mod.ALWAYS_NEVER_AUTOFIX),
            "versions": [_version_json(v) for v in versions],
            "repositories": queries.repositories(session)}


@app.post("/api/policy")
def publish_policy(body: PolicyIn, request: Request, actor: User = Depends(authorize),
                   session: Session = Depends(get_session)):
    """Publish a new version. Versions are never edited; this one takes effect on the next run."""
    try:
        parsed = policy_mod.from_dict(body.content)
    except policy_mod.PolicyError as exc:
        raise HTTPException(422, str(exc)) from exc
    latest = session.scalar(select(func.max(PolicyVersion.version))) or 0
    content = parsed.to_dict()
    content.pop("version", None)
    row = PolicyVersion(version=latest + 1, content=content, note=body.note.strip(),
                        published_by=actor.email, published_at=now())
    session.add(row)
    record(session, "policy_published", actor=actor, target=f"{POLICY_NAME} v{row.version}",
           detail={"note": row.note, "content": content}, ip=client_ip(request))
    session.commit()
    return _version_json(row)


@app.get("/api/policy/active")
def active_policy(repository: str = Query(..., max_length=200), branch: str = Query(..., max_length=200),
                  session: Session = Depends(get_session)):
    """For the pipeline: the policy in force for this repository and branch."""
    latest = session.scalar(select(PolicyVersion).order_by(PolicyVersion.version.desc()).limit(1))
    if latest is None:
        return {"applies": False}
    parsed = policy_mod.from_dict(latest.content, version=latest.version)
    if not parsed.applies_to(repository, branch):
        return {"applies": False, "version": latest.version}
    return {"applies": True, "policy": parsed.to_dict()}


@app.get("/api/rules")
def rules(session: Session = Depends(get_session)):
    """Every rule that has produced a finding, with what the policy does about it."""
    latest = session.scalar(select(PolicyVersion).order_by(PolicyVersion.version.desc()).limit(1))
    active = policy_mod.from_dict(latest.content, latest.version) if latest else policy_mod.STRICT
    rows = session.execute(
        select(FindingRow.rule_id, FindingRow.cwe, FindingRow.severity, func.count(FindingRow.id),
               func.max(Run.started_at))
        .join(Run, FindingRow.run_id == Run.id).where(Run.dry_run.is_(False))
        .group_by(FindingRow.rule_id, FindingRow.cwe, FindingRow.severity)).all()
    by_rule: dict[str, dict] = {}
    for rule_id, cwe, severity, count, last in rows:
        item = by_rule.setdefault(rule_id, {"rule_id": rule_id, "cwe": queries.cwe_id(cwe), "severity": severity,
                                            "pack": _pack(rule_id), "findings": 0, "last_seen": None})
        item["findings"] += count
        if item["last_seen"] is None or queries.iso(last) > item["last_seen"]:
            item["last_seen"], item["severity"] = queries.iso(last), severity
    order = {s: i for i, s in enumerate(policy_mod.SEVERITIES)}
    items = sorted(by_rule.values(), key=lambda r: (order.get(r["severity"], 9), r["rule_id"]))
    for item in items:
        item["gate_action"] = active.action_for(item["severity"])
    return {"policy_version": active.version, "total": len(items), "items": items}


def _pack(rule_id: str) -> str:
    if rule_id.startswith("osv."):
        return "osv-scanner (dependencies)"
    if rule_id.startswith("gitleaks."):
        return "gitleaks (secrets)"
    if "." not in rule_id:
        return "Custom (rules/)"
    return "Semgrep registry"


@app.get("/api/audit")
def audit(action: str | None = Query(None, max_length=64),
          limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
          session: Session = Depends(get_session)):
    stmt = select(AuditEvent)
    count = select(func.count(AuditEvent.id))
    if action:
        stmt = stmt.where(AuditEvent.action == action)
        count = count.where(AuditEvent.action == action)
    rows = session.scalars(stmt.order_by(AuditEvent.at.desc(), AuditEvent.id.desc())
                           .offset(offset).limit(limit)).all()
    return {"total": session.scalar(count) or 0, "items": [{
        "id": e.id, "at": queries.iso(e.at), "actor_email": e.actor_email, "action": e.action,
        "outcome": e.outcome, "target": e.target, "detail": e.detail, "ip": e.ip,
    } for e in rows]}


@app.get("/api/{rest:path}")
def api_not_found(rest: str):
    raise HTTPException(404, "no such API endpoint")


# ---- SPA -------------------------------------------------------------------

@app.get("/{path:path}", include_in_schema=False)
def spa(path: str, settings: Settings = Depends(get_settings)):
    dist = os.path.realpath(settings.web_dist)
    candidate = os.path.realpath(os.path.join(dist, path))
    if path and candidate.startswith(dist + os.sep) and os.path.isfile(candidate):
        cache = "public, max-age=31536000, immutable" if "/assets/" in candidate else "no-cache"
        return FileResponse(candidate, headers={"Cache-Control": cache})
    index = os.path.join(dist, "index.html")
    if not os.path.isfile(index):
        return Response("Dashboard UI not built: run `npm run build` in ui/web.", status_code=503,
                        media_type="text/plain")
    return FileResponse(index, headers={"Cache-Control": "no-cache"})
