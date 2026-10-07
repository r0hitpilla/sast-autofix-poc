import copy
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from dashboard import api  # noqa: E402
from dashboard.auth import hash_password  # noqa: E402
from dashboard.db import Base, User, make_sessionmaker  # noqa: E402
from dashboard.ingest import ingest  # noqa: E402

NOW = datetime.now(timezone.utc)
ADMIN_PASSWORD = "correct horse battery"


def finding(fp, line, cwe, severity, route, outcome, validated=False, attempts=None, score=0.9):
    return {
        "fingerprint": fp,
        "finding": {"file": "app.py", "line": line, "rule_id": f"rule.{fp}", "cwe": cwe,
                    "message": "m", "snippet": f"code {fp}", "severity": severity,
                    "owasp": ["A03:2021 - Injection"], "end_line": line},
        "triage": {"laya_score": score, "route": route, "llm_label": "tp", "rounds": 1,
                   "context": f"{line - 1} | before\n{line} | flagged()\n{line + 1} | after",
                   "evidence": [{"key": "Initial analysis", "question": "Initial analysis",
                                 "answer": "bad\nVERDICT: TRUE POSITIVE — x"},
                                {"key": "sanitization", "question": "Is it sanitized?",
                                 "answer": "No.\nVERDICT: nothing escapes it"}]},
        "outcome": outcome,
        "fix": None if attempts is None else {
            "validated": validated, "scanner_clean": validated, "attempts": attempts,
            "failure": None if validated else "still flagged", "note": None,
            "diff": "+safe()\n" if validated else None, "created_files": [],
            "check_output": "9 passed", "last_proposal": None if validated else "x"},
    }


def report(run_id, *, repo="o/r", branch="SV", hours_ago=1, findings=None, fixed=0,
           gate_passed=False, pr=None, dry_run=False, mode="fix"):
    findings = findings if findings is not None else []
    started = NOW - timedelta(hours=hours_ago)
    confirmed = sum(1 for f in findings if f["triage"]["route"] == "fix")
    review = sum(1 for f in findings if f["triage"]["route"] == "review")
    rejected = sum(1 for f in findings if f["triage"]["route"] == "reject")
    return {
        "schema_version": 2, "target": f"{repo} @ {branch}",
        "run": {"id": run_id, "url": f"https://github.com/{repo}/actions/runs/{run_id}",
                "trigger": "push", "repository": repo, "base_branch": branch,
                "fix_branch": f"{branch}-fix", "commit": "abc123", "mode": mode, "dry_run": dry_run,
                "started_at": started.isoformat(),
                "finished_at": (started + timedelta(minutes=7)).isoformat()},
        "provenance": {"triage_model": "qwen3.5:35b-a3b", "triage_max_rounds": 3,
                       "generation": {"temperature": 0.2, "seed": 42}},
        "pull_request": {"url": f"https://github.com/{repo}/pull/{pr}", "number": pr,
                         "head": f"{branch}-fix", "base": branch} if pr else None,
        "fix_branch_status": {"sha": "def456", "state": "success", "description": "clean"} if pr else None,
        "gate": {"passed": gate_passed, "blocking": confirmed + review},
        "summary": {"scanned": len(findings), "confirmed": confirmed, "fixed": fixed,
                    "review": review, "rejected": rejected, "blocking": confirmed + review, "residual": 0},
        "findings": findings, "residual": [],
        "timings": {"scan": 3.1, "triage (Laya + LLM)": 150.0, "fix + rescan loop": 270.0, "final rescan": 3.0},
        "pr_urls": [],
    }


@pytest.fixture
def Session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return make_sessionmaker(engine)


@pytest.fixture
def seeded(Session):
    """SV: older run (2 open), then newer run (1 fixed, 1 review, 1 reject) with PR #7.
    main: one passing run. A dry run that must be ignored everywhere."""
    ingest(report("100", hours_ago=30, findings=[
        finding("aaa", 42, "CWE-89: Improper ('SQL Injection')", "Critical", "fix", "fix applied but failed validation", attempts=4),
        finding("bbb", 54, "CWE-22: Improper ('Path Traversal')", "High", "fix", "no usable fix from the llm", attempts=4),
    ]), Session)
    ingest(report("101", hours_ago=2, fixed=1, pr=7, findings=[
        finding("aaa", 44, "CWE-89: Improper ('SQL Injection')", "Critical", "fix", "fixed and validated", validated=True, attempts=1),
        finding("ccc", 60, "CWE-79: Improper ('Cross-site Scripting')", "Medium", "review", "sent to review", score=0.6),
        finding("ddd", 70, "CWE-327: Use of a Broken or Risky Cryptographic Algorithm", "Low", "reject", "rejected (likely false positive)", score=0.2),
    ]), Session)
    ingest(report("200", branch="main", hours_ago=5, gate_passed=True), Session)
    ingest(report("999", hours_ago=1, dry_run=True, findings=[
        finding("zzz", 1, "CWE-1: x", "Critical", "fix", "fixed and validated", validated=True, attempts=1)]), Session)
    return Session


@pytest.fixture
def client(seeded, monkeypatch, tmp_path):
    def override():
        with seeded() as s:
            yield s
    api.app.dependency_overrides[api.get_session] = override
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<html>app</html>")
    (dist / "assets" / "app.js").write_text("js")
    monkeypatch.setenv("SAST_WEB_DIST", str(dist))
    with seeded() as s:
        s.add(User(email="admin@example.com", name="Admin", role="admin",
                   password_hash=hash_password(ADMIN_PASSWORD), active=True, created_at=NOW))
        s.commit()
    client = TestClient(api.app)
    # Existing tests exercise the data API; they run as a signed-in admin.
    assert client.post("/api/auth/login", json={"name": "admin",
                                                "password": ADMIN_PASSWORD}).status_code == 200
    yield client
    api.app.dependency_overrides.clear()


@pytest.fixture
def make_report():
    return lambda *a, **k: copy.deepcopy(report(*a, **k))
