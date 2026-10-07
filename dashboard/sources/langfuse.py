"""Read-only access to the self-hosted Langfuse, for the AI-call views.

The dashboard fetches a call's prompt and reply from Langfuse on demand,
server-side with the project's API keys, so the people viewing it need no
Langfuse login and the dashboard's own roles decide who sees what. Nothing is
copied into the dashboard's database: prompts contain source code, so they stay
in Langfuse and are read only when someone asks for them.

Any failure is reported as "unavailable", never raised into the page.
"""

import os

import httpx

import observability

from ..settings import get_settings
from .cache import ttl_cache

TIMEOUT = 8.0
MAX_CHARS = 60_000   # per field; longer text is cut and marked


def credentials(env=None, key_file=observability.KEY_FILE):
    """(host, public key, secret key) from the environment, else the private
    key file the pipeline uses; None when Langfuse isn't set up."""
    env = os.environ if env is None else env
    stored = observability.read_key_file(key_file)
    get = lambda name: env.get(name) or stored.get(name)  # noqa: E731
    host, public, secret = get("LANGFUSE_HOST"), get("LANGFUSE_PUBLIC_KEY"), get("LANGFUSE_SECRET_KEY")
    return (host.rstrip("/"), public, secret) if host and public and secret else None


def public_base(creds) -> str | None:
    """Where a person's browser reaches Langfuse (it can differ from the address
    the server uses, e.g. behind a tunnel or proxy)."""
    settings = get_settings()
    return (settings.langfuse_public_url or (creds[0] if creds else None) or "").rstrip("/") or None


def trace_url(trace_id: str | None, span_id: str | None = None, creds=None) -> str | None:
    creds = creds or credentials()
    base = public_base(creds)
    if not (base and trace_id):
        return None
    url = f"{base}/project/{get_settings().langfuse_project_id}/traces/{trace_id}"
    return f"{url}?observation={span_id}" if span_id else url


def _cut(text):
    if text is None:
        return None, False
    text = text if isinstance(text, str) else str(text)
    return (text[:MAX_CHARS], True) if len(text) > MAX_CHARS else (text, False)


@ttl_cache(60)
def fetch_content(trace_id: str, span_id: str) -> dict:
    """{"available": True, "input", "output", "truncated"} or {"available": False, "reason"}."""
    creds = credentials()
    if creds is None:
        return {"available": False, "reason": "Langfuse is not set up on this server."}
    host, public, secret = creds
    try:
        cursor = None
        while True:
            params = {"traceId": trace_id, "limit": 1000, "fields": "core,basic,io"}
            if cursor:
                params["cursor"] = cursor
            resp = httpx.get(f"{host}/api/public/v2/observations", params=params, auth=(public, secret), timeout=TIMEOUT)
            resp.raise_for_status()
            body = resp.json()
            for obs in body.get("data", []):
                if obs.get("id") == span_id:
                    prompt, cut_in = _cut(obs.get("input"))
                    reply, cut_out = _cut(obs.get("output"))
                    if prompt is None and reply is None:
                        return {"available": False, "reason": "Langfuse holds no prompt or reply for this call "
                                                               "(tracing ran with capture_content off)."}
                    return {"available": True, "input": prompt, "output": reply, "truncated": cut_in or cut_out}
            cursor = (body.get("meta") or {}).get("cursor")
            if not cursor:
                return {"available": False, "reason": "Langfuse has no record of this call (deleted or not yet processed)."}
    except (httpx.HTTPError, ValueError) as exc:
        return {"available": False, "reason": f"Langfuse could not be reached ({type(exc).__name__})."}
