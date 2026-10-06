"""FastAPI app: JSON API under /api, the built React app everywhere else.

Phase 1 is read-only and has no sign-in, so it must only listen on
127.0.0.1 (see README "Dashboard"). Run:

    dashboard/.venv/bin/uvicorn dashboard.api:app --host 127.0.0.1 --port 8710
"""

import csv
import io
import os
import re
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select, text
from sqlalchemy.orm import Session

from . import queries
from .auth import (COOKIE, MIN_PASSWORD_LENGTH, ROLE_LABELS, ROLES, SESSION_TTL, authorize,
                   burn_password_time, client_ip, hash_password, lockout_active, now,
                   permissions_for, record, revoke_user_sessions, start_session, token_hash,
                   verify_password)
from .db import AuditEvent, AuthSession, User
from .deps import get_session
from .settings import Settings, get_settings
from .sources import github, ollama, system

VERSION = "1.1.0"

app = FastAPI(title="SAST Autofix dashboard", version=VERSION, docs_url="/api/docs",
              openapi_url="/api/openapi.json", redoc_url=None,
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
