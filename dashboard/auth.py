"""Sign-in, sessions, roles and the audit trail.

Everything under /api/ except the public paths below needs a signed-in user
whose role grants the permission that path requires. One table (PATH_RULES)
says which permission each area needs, so the rules are in one place.

Sessions are server-side: the browser holds a random token, the database
holds its hash. Logging out or disabling a user revokes the session at once.
"""

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from .db import AuditEvent, AuthSession, User
from .deps import get_session
from .settings import get_settings

ROLES = {
    "admin": {"dashboard:read", "findings:act", "users:manage", "audit:read",
              "integrations:read", "integrations:manage", "policy:manage"},
    "security_engineer": {"dashboard:read", "findings:act", "integrations:read", "policy:manage"},
    "developer": {"dashboard:read"},
    "auditor": {"dashboard:read", "audit:read"},
}
ROLE_LABELS = {"admin": "Admin", "security_engineer": "Security Engineer",
               "developer": "Developer", "auditor": "Auditor"}

COOKIE = "sast_session"
SESSION_TTL = timedelta(hours=12)
MIN_PASSWORD_LENGTH = 12
LOCKOUT_FAILURES = 5
LOCKOUT_WINDOW = timedelta(minutes=15)

PUBLIC_PATHS = {"/api/auth/login", "/api/livez"}
# Read by the pipeline with its machine token; everything else needs a user.
MACHINE_PATHS = {"/api/history", "/api/policy/active"}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ---- passwords -------------------------------------------------------------

def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, salt_hex, digest_hex = stored.split("$")
        if algorithm != "scrypt":
            return False
        computed = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex),
                                  n=2**14, r=8, p=1, dklen=32)
        return hmac.compare_digest(computed, bytes.fromhex(digest_hex))
    except ValueError:
        return False


_DUMMY_HASH = None


def burn_password_time() -> None:
    """Spend the same time on an unknown email as on a known one, so the
    response doesn't reveal which emails have accounts."""
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password("dummy-password-never-used")
    verify_password("wrong-password", _DUMMY_HASH)


# ---- audit -----------------------------------------------------------------

def record(session: Session, action: str, outcome: str = "success", *, actor: User | None = None,
           actor_email: str | None = None, target: str | None = None, detail: dict | None = None,
           ip: str | None = None) -> None:
    session.add(AuditEvent(
        at=now(), actor_id=actor.id if actor else None,
        actor_email=(actor.email if actor else actor_email),
        action=action, outcome=outcome, target=target, detail=detail or {}, ip=ip,
    ))


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


# ---- sessions --------------------------------------------------------------

def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def start_session(session: Session, user: User, request: Request) -> str:
    token = secrets.token_urlsafe(32)
    session.add(AuthSession(
        token_hash=token_hash(token), user_id=user.id, created_at=now(),
        expires_at=now() + SESSION_TTL, ip=client_ip(request),
        user_agent=(request.headers.get("user-agent") or "")[:300],
    ))
    return token


def revoke_user_sessions(session: Session, user_id: int) -> None:
    session.execute(delete(AuthSession).where(AuthSession.user_id == user_id))


def current_user(request: Request, session: Session) -> User | None:
    token = request.cookies.get(COOKIE)
    if not token:
        return None
    row = session.get(AuthSession, token_hash(token))
    if row is None:
        return None
    if _aware(row.expires_at) < now():
        session.delete(row)
        return None
    user = session.get(User, row.user_id)
    return user if user and user.active else None


def permissions_for(role: str) -> set[str]:
    return ROLES.get(role, set())


def required_permission(path: str, method: str = "GET") -> str | None:
    """The permission a /api/ path needs, or None when signing in is enough."""
    if path.startswith("/api/users"):
        return "users:manage"
    if path.startswith("/api/audit"):
        return "audit:read"
    if path.startswith("/api/policy") and method not in SAFE_METHODS:
        return "policy:manage"
    if path.startswith("/api/integrations"):
        return "integrations:read" if method in SAFE_METHODS else "integrations:manage"
    if method not in SAFE_METHODS and path.startswith("/api/findings/"):
        return "findings:act"
    return "dashboard:read"


def _machine_token_ok(request: Request) -> bool:
    expected = get_settings().history_token
    header = request.headers.get("authorization", "")
    if not expected or not header.startswith("Bearer "):
        return False
    return hmac.compare_digest(header[len("Bearer "):].encode(), expected.encode())


def lockout_active(session: Session, email: str) -> bool:
    since = now() - LOCKOUT_WINDOW
    failures = session.scalar(
        select(func.count(AuditEvent.id)).where(
            AuditEvent.action == "login_failed", AuditEvent.target == email, AuditEvent.at >= since)
    ) or 0
    return failures >= LOCKOUT_FAILURES


# ---- the one check every API request passes through -------------------------

def authorize(request: Request, session: Session = Depends(get_session)):
    """Attached to the whole app. Returns the signed-in user (or None for
    public paths and the SPA); raises 401/403/415 otherwise."""
    path = request.url.path
    if not path.startswith("/api/") or path in PUBLIC_PATHS:
        return None
    if path in MACHINE_PATHS and request.method in SAFE_METHODS and _machine_token_ok(request):
        return None
    user = current_user(request, session)
    if user is None:
        raise HTTPException(401, "sign in required")
    needed = required_permission(path, request.method)
    if needed and needed not in permissions_for(user.role):
        record(session, "access_denied", "denied", actor=user, target=f"{request.method} {path}",
               detail={"needs": needed}, ip=client_ip(request))
        session.commit()
        raise HTTPException(403, "your role does not allow this")
    return user
