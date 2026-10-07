"""Connections to outside systems: source control, notifications, ticketing.

Each provider in PROVIDERS says which settings it takes, which are secret,
which events it can receive, and how to test it. A provider without a
connector is listed as unavailable, never shown as connected.

Secrets are encrypted with Fernet (SAST_SECRET_KEY) and never returned by
the API, only whether each one is set.

Notifications go through an outbox: ingest (which runs in CI and holds no
key) queues a message; the dashboard service delivers it and retries.
"""

import json
import smtplib
import ssl
from datetime import timedelta
from email.message import EmailMessage
from urllib.parse import urlparse

import httpx
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import Integration, OutboxMessage, Run
from .settings import get_settings

TIMEOUT = 10.0
MAX_ATTEMPTS = 6

# Events a run can raise. ingest queues each one for every integration that wants it.
EVENTS = {
    "gate_blocked": "Merge gate blocked",
    "fix_pr_opened": "Fix pull request opened",
    "run_completed": "Scan completed",
}

# Catalogue, in the design's order. `fields`: (key, label, secret?, required?).
CATALOGUE = [
    ("Source control", [
        {"key": "github", "name": "GitHub", "available": True, "auth": "API token",
         "fields": [("token", "Personal access token (read-only is enough)", True, True),
                    ("repositories", "Repositories (owner/name, comma-separated; blank = all)", False, False)],
         "permissions": ["contents: read", "pull_requests: read", "metadata: read"],
         "events": []},
        {"key": "gitlab", "name": "GitLab", "available": False},
        {"key": "bitbucket", "name": "Bitbucket", "available": False},
    ]),
    ("CI/CD", [
        {"key": "github_actions", "name": "GitHub Actions", "available": True, "builtin": True},
        {"key": "gitlab_ci", "name": "GitLab CI", "available": False},
        {"key": "jenkins", "name": "Jenkins", "available": False},
        {"key": "azure_devops", "name": "Azure DevOps", "available": False},
    ]),
    ("Notifications", [
        {"key": "slack", "name": "Slack", "available": True, "auth": "Incoming webhook",
         "fields": [("webhook_url", "Incoming webhook URL", True, True)],
         "events": list(EVENTS)},
        {"key": "teams", "name": "Microsoft Teams", "available": True, "auth": "Incoming webhook",
         "fields": [("webhook_url", "Incoming webhook URL", True, True)],
         "events": list(EVENTS)},
        {"key": "email", "name": "Email", "available": True, "auth": "SMTP",
         "fields": [("host", "SMTP host", False, True), ("port", "Port (587 STARTTLS, 465 TLS)", False, True),
                    ("username", "Username", False, False), ("password", "Password", True, False),
                    ("from_addr", "From address", False, True), ("to", "Recipients (comma-separated)", False, True)],
         "events": list(EVENTS)},
    ]),
    ("Ticketing", [
        {"key": "jira", "name": "Jira", "available": True, "auth": "API token",
         "fields": [("base_url", "Site URL (https://your-site.atlassian.net)", False, True),
                    ("email", "Account email", False, True), ("api_token", "API token", True, True),
                    ("project_key", "Project key", False, True)],
         "events": []},
        {"key": "linear", "name": "Linear", "available": False},
        {"key": "servicenow", "name": "ServiceNow", "available": False},
    ]),
    ("Security", [
        {"key": "webhook", "name": "SIEM / webhook", "available": True, "auth": "Signed webhook",
         "fields": [("url", "Endpoint URL (https)", False, True),
                    ("signing_secret", "Signing secret (HMAC-SHA256)", True, True)],
         "events": list(EVENTS)},
        {"key": "defectdojo", "name": "DefectDojo", "available": False},
        {"key": "snyk", "name": "Snyk", "available": False},
        {"key": "dependency_scanners", "name": "Dependency scanners", "available": True, "builtin": True},
    ]),
]
PROVIDERS = {p["key"]: p for _, items in CATALOGUE for p in items}


class IntegrationError(ValueError):
    """Bad settings, or the outside system refused us. The message is shown to the admin."""


# ---- secrets ---------------------------------------------------------------

def _fernet() -> Fernet:
    key = get_settings().secret_key
    if not key:
        raise IntegrationError("SAST_SECRET_KEY is not set on the dashboard server, so secrets can't be stored")
    try:
        return Fernet(key.encode())
    except ValueError as exc:
        raise IntegrationError("SAST_SECRET_KEY is not a valid Fernet key") from exc


def encrypt(secrets: dict) -> str:
    return _fernet().encrypt(json.dumps(secrets).encode()).decode()


def decrypt(blob: str) -> dict:
    try:
        return json.loads(_fernet().decrypt(blob.encode()))
    except InvalidToken as exc:
        raise IntegrationError("stored secrets can't be decrypted (was SAST_SECRET_KEY changed?)") from exc


# ---- settings validation ---------------------------------------------------

def _https(url: str, label: str) -> str:
    url = url.strip()
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise IntegrationError(f"{label} must be an https:// URL")
    return url


def split_settings(provider: str, values: dict, existing_secrets: dict | None = None) -> tuple[dict, dict]:
    """(config, secrets) from submitted values. A blank secret keeps the stored one,
    so editing other settings doesn't require re-entering it."""
    spec = PROVIDERS.get(provider)
    if not spec or not spec.get("available") or spec.get("builtin"):
        raise IntegrationError("this provider can't be configured yet")
    config, secrets = {}, dict(existing_secrets or {})
    for key, label, secret, required in spec["fields"]:
        value = str(values.get(key, "") or "").strip()
        if secret:
            if value:
                secrets[key] = value
            elif required and not secrets.get(key):
                raise IntegrationError(f"{label} is required")
        else:
            if required and not value:
                raise IntegrationError(f"{label} is required")
            config[key] = value
    if provider in ("slack", "teams"):
        _https(secrets["webhook_url"], "Webhook URL")
    if provider == "webhook":
        config["url"] = _https(config["url"], "Endpoint URL")
    if provider == "jira":
        config["base_url"] = _https(config["base_url"], "Site URL").rstrip("/")
    if provider == "email":
        try:
            config["port"] = str(int(config["port"]))
        except ValueError as exc:
            raise IntegrationError("Port must be a number") from exc
    if provider == "github":
        repos = [r.strip() for r in config.get("repositories", "").split(",") if r.strip()]
        for r in repos:
            if r.count("/") != 1:
                raise IntegrationError(f"{r!r} is not owner/name")
        config["repositories"] = ", ".join(repos)
    return config, secrets


def valid_events(provider: str, events: list) -> list:
    allowed = PROVIDERS[provider].get("events", [])
    unknown = [e for e in events if e not in allowed]
    if unknown:
        raise IntegrationError(f"{PROVIDERS[provider]['name']} can't receive: {', '.join(unknown)}")
    return list(dict.fromkeys(events))


# ---- talking to the outside world -----------------------------------------

def client() -> httpx.Client:
    """Overridden in tests. No redirects: a webhook that redirects is not trusted."""
    return httpx.Client(timeout=TIMEOUT, follow_redirects=False)


def _check(resp: httpx.Response, what: str) -> None:
    if resp.status_code >= 400:
        raise IntegrationError(f"{what}: HTTP {resp.status_code}")


def _post_json(url: str, body: dict, headers: dict | None = None) -> None:
    with client() as c:
        _check(c.post(url, json=body, headers=headers or {}), "the endpoint refused the message")


def _signed_post(url: str, signing_secret: str, body: dict) -> None:
    import hashlib
    import hmac
    raw = json.dumps(body, separators=(",", ":")).encode()
    signature = hmac.new(signing_secret.encode(), raw, hashlib.sha256).hexdigest()
    with client() as c:
        resp = c.post(url, content=raw, headers={"Content-Type": "application/json",
                                                 "X-SAST-Signature": f"sha256={signature}"})
    _check(resp, "the endpoint refused the message")


def _send_email(config: dict, secrets: dict, subject: str, text: str) -> None:
    msg = EmailMessage()
    msg["Subject"], msg["From"] = subject, config["from_addr"]
    msg["To"] = ", ".join(a.strip() for a in config["to"].split(",") if a.strip())
    msg.set_content(text)
    port = int(config["port"])
    context = ssl.create_default_context()
    try:
        if port == 465:
            server = smtplib.SMTP_SSL(config["host"], port, timeout=TIMEOUT, context=context)
        else:
            server = smtplib.SMTP(config["host"], port, timeout=TIMEOUT)
            server.starttls(context=context)
        with server:
            if config.get("username"):
                server.login(config["username"], secrets.get("password", ""))
            server.send_message(msg)
    except (OSError, smtplib.SMTPException) as exc:
        raise IntegrationError(f"SMTP: {exc}") from exc


def message_text(event: str, payload: dict) -> str:
    run = payload.get("run", {})
    where = f"{run.get('repository')} @ {run.get('branch')}"
    lines = [f"{EVENTS.get(event, event)}: {where}"]
    if event == "gate_blocked":
        lines.append(f"{payload.get('blocking', 0)} finding(s) block the merge.")
    if payload.get("fixed"):
        lines.append(f"{payload['fixed']} fix(es) validated.")
    if payload.get("pr_url"):
        lines.append(f"Fix PR: {payload['pr_url']}")
    lines.append(f"Details: {payload.get('link')}")
    return "\n".join(lines)


def send(integration: Integration, event: str, payload: dict) -> None:
    """Deliver one event. Raises IntegrationError on failure."""
    secrets = decrypt(integration.secret_enc)
    text = message_text(event, payload)
    p = integration.provider
    if p == "slack":
        _post_json(secrets["webhook_url"], {"text": text})
    elif p == "teams":
        _post_json(secrets["webhook_url"], {"text": text.replace("\n", "  \n")})
    elif p == "email":
        _send_email(integration.config, secrets, f"[SAST Autofix] {text.splitlines()[0]}", text)
    elif p == "webhook":
        _signed_post(integration.config["url"], secrets["signing_secret"], {"event": event, **payload})
    else:
        raise IntegrationError(f"{p} does not receive events")


# ---- connection tests (the wizard's "Test connection" step) -----------------

def test_connection(provider: str, config: dict, secrets: dict) -> list[dict]:
    """Each check as {"check", "ok", "detail"}. Never raises for a failed check."""
    results = []

    def check(name, fn):
        try:
            detail = fn()
            results.append({"check": name, "ok": True, "detail": detail or "ok"})
            return True
        except (IntegrationError, httpx.HTTPError, OSError, KeyError, ValueError) as exc:
            results.append({"check": name, "ok": False, "detail": str(exc) or type(exc).__name__})
            return False

    if provider == "github":
        headers = {"Authorization": f"Bearer {secrets['token']}", "Accept": "application/vnd.github+json"}

        def auth():
            with client() as c:
                r = c.get("https://api.github.com/user", headers=headers)
            _check(r, "token rejected")
            return f"signed in as {r.json().get('login')}"

        if check("Authentication", auth):
            repos = [r.strip() for r in config.get("repositories", "").split(",") if r.strip()]
            for repo in repos:
                def access(repo=repo):
                    with client() as c:
                        r = c.get(f"https://api.github.com/repos/{repo}", headers=headers)
                    _check(r, f"{repo} not readable")
                    return f"{repo} readable"
                check(f"Repository access: {repo}", access)
    elif provider in ("slack", "teams"):
        check("Webhook delivery", lambda: _post_json(
            secrets["webhook_url"], {"text": "SAST Autofix: test message. This channel will receive security notifications."}))
    elif provider == "email":
        check("Send test email", lambda: _send_email(
            config, secrets, "[SAST Autofix] Test message", "This address will receive SAST Autofix notifications."))
    elif provider == "jira":
        def jira_project():
            with client() as c:
                r = c.get(f"{config['base_url']}/rest/api/3/project/{config['project_key']}",
                          auth=(config["email"], secrets["api_token"]))
            _check(r, "project not readable with these credentials")
            return f"project {r.json().get('key')} ({r.json().get('name')})"
        check("Authentication and project access", jira_project)
    elif provider == "webhook":
        check("Webhook delivery", lambda: _signed_post(
            config["url"], secrets["signing_secret"], {"event": "test", "message": "SAST Autofix test"}))
    else:
        results.append({"check": "Connector", "ok": False, "detail": "no connector for this provider"})
    return results


# ---- Jira issues -----------------------------------------------------------

def create_jira_issue(integration: Integration, summary: str, description: str) -> tuple[str, str]:
    """(issue key, browse URL)."""
    config, secrets = integration.config, decrypt(integration.secret_enc)
    body = {"fields": {
        "project": {"key": config["project_key"]},
        "summary": summary[:250],
        "issuetype": {"name": "Bug"},
        "description": {"type": "doc", "version": 1, "content": [
            {"type": "paragraph", "content": [{"type": "text", "text": line or " "}]}
            for line in description.splitlines()]},
    }}
    with client() as c:
        r = c.post(f"{config['base_url']}/rest/api/3/issue", json=body,
                   auth=(config["email"], secrets["api_token"]))
    _check(r, "Jira refused the issue")
    key = r.json()["key"]
    return key, f"{config['base_url']}/browse/{key}"


# ---- outbox ----------------------------------------------------------------

def run_events(run: Run) -> list[str]:
    if run.dry_run:
        return []
    events = ["run_completed"]
    if run.gate_passed is False:
        events.append("gate_blocked")
    if run.pr_number:
        events.append("fix_pr_opened")
    return events


def enqueue_for_run(session: Session, run: Run) -> int:
    """Queue this run's events for every enabled integration that wants them.
    Re-ingesting the same run queues nothing new."""
    events = run_events(run)
    if not events:
        return 0
    link = f"{get_settings().public_url.rstrip('/')}/runs/{run.id}"
    payload = {
        "run": {"id": run.id, "repository": run.repository, "branch": run.base_branch, "url": run.url},
        "blocking": run.blocking, "fixed": run.fixed, "pr_url": run.pr_url, "link": link,
    }
    queued = 0
    now = _now()
    for integration in session.scalars(select(Integration).where(Integration.enabled.is_(True))).all():
        for event in events:
            if event not in (integration.events or []):
                continue
            exists = session.scalar(select(OutboxMessage.id).where(
                OutboxMessage.integration_id == integration.id, OutboxMessage.event == event,
                OutboxMessage.run_id == run.id))
            if exists:
                continue
            session.add(OutboxMessage(integration_id=integration.id, event=event, run_id=run.id,
                                      payload=payload, created_at=now, attempts=0, next_attempt_at=now))
            queued += 1
    return queued


def _now():
    from .auth import now
    return now()


def deliver_pending(session: Session, limit: int = 20) -> int:
    """Send what's due; back off exponentially on failure. Returns how many were sent."""
    stmt = (select(OutboxMessage).where(OutboxMessage.delivered_at.is_(None),
                                        OutboxMessage.attempts < MAX_ATTEMPTS,
                                        OutboxMessage.next_attempt_at <= _now())
            .order_by(OutboxMessage.id).limit(limit))
    if session.get_bind().dialect.name == "postgresql":
        stmt = stmt.with_for_update(skip_locked=True)  # two workers never send the same message
    sent = 0
    for msg in session.scalars(stmt).all():
        integration = session.get(Integration, msg.integration_id)
        msg.attempts += 1
        try:
            if integration is None or not integration.enabled:
                raise IntegrationError("integration disabled")
            send(integration, msg.event, msg.payload)
            msg.delivered_at = _now()
            msg.last_error = None
            integration.last_event_at = msg.delivered_at
            integration.last_error = None
            sent += 1
        except (IntegrationError, httpx.HTTPError, OSError, KeyError) as exc:
            msg.last_error = (str(exc) or type(exc).__name__)[:500]
            msg.next_attempt_at = _now() + timedelta(minutes=2 ** msg.attempts)
            if integration is not None:
                integration.last_error = msg.last_error
    session.commit()
    return sent
