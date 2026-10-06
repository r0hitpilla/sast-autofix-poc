"""FastAPI app: JSON API under /api, the built React app everywhere else.

Phase 1 is read-only and has no sign-in, so it must only listen on
127.0.0.1 (see README "Dashboard"). Run:

    dashboard/.venv/bin/uvicorn dashboard.api:app --host 127.0.0.1 --port 8710
"""

import csv
import io
import os
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from sqlalchemy import text
from sqlalchemy.orm import Session

from . import queries
from .db import make_sessionmaker
from .settings import Settings, get_settings
from .sources import github, ollama, system

VERSION = "1.0.0"
_sessionmaker = None


def get_session() -> Iterator[Session]:
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = make_sessionmaker()
    with _sessionmaker() as session:
        yield session


app = FastAPI(title="SAST Autofix dashboard", version=VERSION, docs_url="/api/docs",
              openapi_url="/api/openapi.json", redoc_url=None)


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
