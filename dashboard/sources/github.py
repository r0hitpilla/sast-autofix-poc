"""Live pull-request state from the GitHub REST API.

Works unauthenticated for public repos (60 requests/hour, hence the cache);
set GITHUB_TOKEN to a read-only token for private repos or higher limits.
Any failure returns {"available": False, ...} — never an exception to the UI.
"""

import httpx

from ..settings import get_settings
from .cache import ttl_cache

API = "https://api.github.com"


def _get(path: str):
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = get_settings().github_token
    if token:
        headers["Authorization"] = f"Bearer {token}"
    resp = httpx.get(f"{API}{path}", headers=headers, timeout=8)
    resp.raise_for_status()
    return resp.json()


@ttl_cache(60)
def pr_state(repository: str, number: int) -> dict:
    try:
        pr = _get(f"/repos/{repository}/pulls/{number}")
        status = _get(f"/repos/{repository}/commits/{pr['head']['sha']}/status")
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        return {"available": False, "error": str(exc)[:200]}
    return {
        "available": True,
        "state": "merged" if pr.get("merged_at") else pr.get("state"),
        "title": pr.get("title"),
        "author": (pr.get("user") or {}).get("login"),
        "reviewers": [u.get("login") for u in pr.get("requested_reviewers") or []],
        "mergeable_state": pr.get("mergeable_state"),
        "additions": pr.get("additions"), "deletions": pr.get("deletions"),
        "changed_files": pr.get("changed_files"),
        "checks": [{"context": s.get("context"), "state": s.get("state"),
                    "description": s.get("description")} for s in status.get("statuses", [])],
    }
