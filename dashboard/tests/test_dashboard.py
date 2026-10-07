import json
from unittest.mock import patch

import pytest
from sqlalchemy import func, select

from dashboard import queries
from dashboard.db import FindingRow, Run, TrackedFinding
from dashboard.ingest import ReportError, ingest, main as ingest_main

from .conftest import finding, report


# ---- ingest ----------------------------------------------------------------

def test_ingest_is_idempotent(Session):
    r = report("1", findings=[finding("a", 1, "CWE-89: x", "High", "fix", "fixed and validated", True, 1)])
    ingest(r, Session)
    ingest(r, Session)
    with Session() as s:
        assert s.scalar(select(func.count(Run.id))) == 1
        assert s.scalar(select(func.count(FindingRow.id))) == 1


def test_ingest_rejects_unknown_schema_versions(Session):
    for bad in ({**report("1"), "schema_version": 1}, {**report("1"), "schema_version": 99}):
        with pytest.raises(ReportError, match="schema_version"):
            ingest(bad, Session)


def test_ingest_cli_reports_errors_without_traceback(tmp_path, capsys):
    path = tmp_path / "r.json"
    path.write_text(json.dumps({"schema_version": 1}))
    assert ingest_main([str(path)]) == 1
    assert "unsupported report schema_version" in capsys.readouterr().err


def test_contract_with_the_pipelines_own_report_writer(Session):
    """Build a report with the pipeline's report.to_json and ingest it."""
    from models import Finding, TriageResult, ValidationResult
    from report import FindingRecord, RunReport, to_json

    f = Finding(file="app.py", line=42, rule_id="r", cwe="CWE-89: x ('SQL Injection')",
                message="m", snippet="q", severity="Critical", owasp=["A03"], end_line=42)
    t = TriageResult(f, "r", 0.9, "fix", evidence=[("Initial analysis", "VERDICT: TRUE POSITIVE — y")],
                     context="42 | q")
    v = ValidationResult(f, True, "9 passed", True, attempts=1, fix_diff="+x\n")
    rr = RunReport(target="o/r @ SV", records=[FindingRecord(t, "fixed and validated", v)])
    rr.meta = {"run": {"id": "c1", "repository": "o/r", "base_branch": "SV",
                       "started_at": "2026-10-06T10:00:00+00:00", "finished_at": "2026-10-06T10:07:00+00:00"},
               "gate": {"passed": False, "blocking": 1}, "provenance": {"triage_model": "m"}}

    run = ingest(json.loads(to_json(rr)), Session)

    assert run.id == "c1" and run.findings[0].fix_validated and run.findings[0].severity == "Critical"
    with Session() as s:
        detail = queries.finding_detail(s, run.findings[0].id)
    assert detail["title"] == "SQL Injection" and detail["code"] == [{"n": 42, "text": "q", "flagged": True}]


# ---- queries ---------------------------------------------------------------

def test_open_findings_come_from_the_latest_run_of_each_branch(seeded):
    with seeded() as s:
        rows = queries.open_findings(s)
    # run 101 (latest SV): aaa (fix) + ccc (review); reject excluded; old run 100 and dry run ignored
    assert sorted(r.fingerprint for r in rows) == ["aaa", "ccc"]


def test_run_status_and_dry_runs_excluded(seeded):
    with seeded() as s:
        runs = {r["id"]: r for r in queries.list_runs(s)["items"]}
    assert "999" not in runs
    assert runs["101"]["status"] == "Fix PR open"
    assert runs["100"]["status"] == "Blocked"
    assert runs["200"]["status"] == "Passed"
    assert runs["101"]["duration_s"] == 420


def test_overview_kpis(seeded):
    with seeded() as s:
        ov = queries.overview(s, days=7)
    k = ov["kpis"]
    assert k["open_findings"] == 2 and k["critical"] == 1
    assert k["fixed"] == 1 and k["autofix_success"] == pytest.approx(1 / 3, abs=1e-4)  # 1 fixed / 3 confirmed
    assert k["blocked_branches"] == 1  # SV red, main green
    assert [p["count"] for p in ov["posture"]] == [1, 0, 1, 0]
    assert {r["repository"] for r in ov["repositories"]} == {"o/r"}
    assert ov["repositories"][0]["status"] == "Blocked"


def test_finding_detail_tracks_the_fingerprint_across_runs(seeded):
    with seeded() as s:
        row = s.scalars(select(FindingRow).where(FindingRow.run_id == "101", FindingRow.fingerprint == "aaa")).one()
        d = queries.finding_detail(s, row.id)
    assert d["times_detected"] == 2  # runs 100 and 101, not the dry run
    assert d["fix_status"] == "Fixed" and d["verdict"] == "True positive"
    assert [l["flagged"] for l in d["code"]] == [False, True, False]
    assert d["investigation"]["questions"][0]["key"] == "sanitization"
    assert d["investigation"]["max_rounds"] == 3


def test_prs_carry_gate_state_of_their_base_branch(seeded):
    with seeded() as s:
        [pr] = queries.list_prs(s)
        detail = queries.pr_detail(s, "o/r", 7)
    assert (pr["number"], pr["head"], pr["base"], pr["gate_passed"]) == (7, "SV-fix", "SV", False)
    assert detail["summary"]["fixed"] == 1 and detail["validation"]["state"] == "success"


def test_report_rates(seeded):
    with seeded() as s:
        rep = queries.report(s, days=30)
    assert rep["kpis"]["findings"] == 5
    assert rep["kpis"]["false_positive_rate"] == pytest.approx(1 / 5, abs=1e-4)
    # attempts: run100 aaa 4 + bbb 4 (all failed), run101 aaa 1 (validated) -> 8 failed / 9
    assert rep["kpis"]["fix_attempt_failure_rate"] == pytest.approx(8 / 9, abs=1e-4)
    assert {b["label"] for b in rep["charts"]["by_cwe"]} == {"CWE-89", "CWE-22", "CWE-79", "CWE-327"}


def test_cwe_title():
    assert queries.cwe_title("CWE-89: Improper Neutralization ... ('SQL Injection')") == "SQL Injection"
    assert queries.cwe_title("CWE-327: Use of a Broken or Risky Cryptographic Algorithm").startswith("Use of a Broken")


# ---- API -------------------------------------------------------------------

def test_api_endpoints(client):
    assert client.get("/api/meta").json()["repositories"] == ["o/r"]
    assert client.get("/api/overview?days=7").json()["kpis"]["open_findings"] == 2
    runs = client.get("/api/runs").json()
    assert runs["total"] == 3 and runs["items"][0]["id"] == "101"
    detail = client.get("/api/runs/101").json()
    assert [st["name"] for st in detail["stages"]] == ["Scan", "Triage", "Fix & validate", "Final rescan"]
    assert len(detail["patches"]) == 1 and detail["patches"][0]["diff"] == "+safe()\n"
    fid = client.get("/api/findings").json()["items"][0]["id"]
    assert client.get(f"/api/findings/{fid}").json()["severity"] == "Critical"
    assert client.get("/api/findings?state=all&severity=Low").json()["total"] == 1


def test_api_validation_and_404s(client):
    assert client.get("/api/runs/nope").status_code == 404
    assert client.get("/api/findings/999999").status_code == 404
    assert client.get("/api/findings?severity=Bogus").status_code == 422
    assert client.get("/api/overview?days=0").status_code == 422
    assert client.get("/api/does-not-exist").status_code == 404


def test_pr_endpoint_merges_live_github_state(client):
    live = {"available": True, "state": "open", "checks": []}
    with patch("dashboard.api.github.pr_state", return_value=live):
        body = client.get("/api/prs/o/r/7").json()
    assert body["live"]["state"] == "open" and body["gate"]["passed"] is False
    assert client.get("/api/prs/o/r/8").status_code == 404


def test_csv_export_neutralises_formula_injection(client, seeded):
    with seeded() as s:
        s.query(FindingRow).filter(FindingRow.fingerprint == "aaa").update({"file": "=HYPERLINK(evil)"})
        s.commit()
    resp = client.get("/api/reports/export.csv")
    assert resp.status_code == 200 and "attachment" in resp.headers["content-disposition"]
    assert "'=HYPERLINK(evil)" in resp.text
    assert client.get("/api/reports/export.xml").status_code == 404


def test_spa_serving_and_security_headers(client):
    index = client.get("/runs/101")
    assert index.text == "<html>app</html>" and index.headers["cache-control"] == "no-cache"
    assert "frame-ancestors 'none'" in index.headers["content-security-policy"]
    assert index.headers["x-frame-options"] == "DENY"
    asset = client.get("/assets/app.js")
    assert asset.text == "js" and "immutable" in asset.headers["cache-control"]
    # path traversal out of the dist dir falls back to index.html, never the file
    assert client.get("/../../etc/passwd").text == "<html>app</html>"


def test_sources_fail_soft():
    import httpx
    from dashboard.sources import github, ollama
    github.pr_state.cache_clear()
    ollama.status.cache_clear()
    with patch("dashboard.sources.github.httpx.get", side_effect=httpx.ConnectError("down")):
        assert github.pr_state("o/r", 1)["available"] is False
    with patch("dashboard.sources.ollama.httpx.get", side_effect=httpx.ConnectError("down")):
        assert ollama.status()["online"] is False


def test_migrations_build_the_same_schema_as_the_models(tmp_path):
    """`alembic upgrade head` must produce exactly the tables/columns db.py declares."""
    import os
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    from dashboard.db import Base

    url = f"sqlite:///{tmp_path / 'm.db'}"
    cfg = Config(os.path.join(os.path.dirname(os.path.dirname(__file__)), "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "head")
    insp = inspect(create_engine(url))
    for table in Base.metadata.tables.values():
        assert {c["name"] for c in insp.get_columns(table.name)} == {c.name for c in table.columns}


def test_dependency_finding_carries_cvss_risk_and_advisory_link(Session):
    from models import Finding, TriageResult, ValidationResult
    from report import FindingRecord, RunReport, to_json

    f = Finding(file="requirements.txt", line=1, rule_id="osv.PYSEC-2026-2151",
                cwe="CWE-1395", message="flask 3.0.0 is affected", snippet="Flask>=3.0.0",
                severity="Medium", end_line=1, cvss=4.3)
    t = TriageResult(f, "r", 0.94, "fix")
    rr = RunReport(target="o/r @ SV", records=[FindingRecord(t, "fixed and validated",
                                                            ValidationResult(f, True, "ok", True))])
    rr.meta = {"run": {"id": "d1", "repository": "o/r", "base_branch": "SV",
                       "started_at": "2026-10-06T10:00:00+00:00", "finished_at": "2026-10-06T10:07:00+00:00"},
               "gate": {"passed": True, "blocking": 0}, "provenance": {}}
    run = ingest(json.loads(to_json(rr)), Session)

    with Session() as s:
        summary = queries.finding_summary(s.get(FindingRow, run.findings[0].id))
    assert summary["cvss"] == 4.3
    assert summary["risk"] is not None and summary["risk"] > 0
    assert summary["advisory_url"] == "https://osv.dev/vulnerability/PYSEC-2026-2151"


def test_advisory_url_only_for_osv_ids():
    assert queries.advisory_url("osv.GHSA-68rp-wp8r-4726") == "https://osv.dev/vulnerability/GHSA-68rp-wp8r-4726"
    assert queries.advisory_url("python.flask.security.open-redirect") is None
    assert queries.advisory_url("osv.bad/../x") is None


# ---- finding identity across runs ------------------------------------------

def test_same_finding_across_branches_and_runs_is_one_finding(Session):
    fp = "ident-1"
    ingest(report("r1", branch="SV", hours_ago=3, findings=[
        finding(fp, 5, "CWE-79: x", "High", "fix", "fixed and validated", True, 1)]), Session)
    ingest(report("r2", branch="SV2", hours_ago=1, findings=[
        finding(fp, 9, "CWE-79: x", "High", "fix", "fixed and validated", True, 2)]), Session)
    with Session() as s:
        tracked = s.get(TrackedFinding, fp)
        assert tracked.occurrences == 2
        assert tracked.first_seen < tracked.last_seen
        listing = queries.list_findings(s, state="all")
    assert listing["total"] == 1
    assert listing["items"][0]["occurrences"] == 2


def test_reingesting_a_run_does_not_double_count(Session):
    fp = "ident-2"
    r = report("r1", findings=[finding(fp, 5, "CWE-79: x", "High", "fix", "fixed and validated", True, 1)])
    ingest(r, Session)
    ingest(r, Session)
    with Session() as s:
        assert s.get(TrackedFinding, fp).occurrences == 1


def test_dry_runs_do_not_create_tracked_findings(Session):
    fp = "ident-3"
    ingest(report("r1", dry_run=True, findings=[finding(fp, 5, "CWE-79: x", "High", "fix", "x")]), Session)
    with Session() as s:
        assert s.get(TrackedFinding, fp) is None


def test_same_code_under_several_rules_is_one_location(Session):
    # One flaw, three rules, one line: one finding with the other rules listed.
    code = "return f'<h1>{name}</h1>'"
    def hit(fp, rule):
        f = finding(fp, 7, "CWE-79: x", "High", "fix", "fixed and validated", True, 1)
        f["finding"]["rule_id"] = rule
        f["finding"]["snippet"] = code
        return f
    ingest(report("r1", findings=[hit("loc-a", "rule.one"), hit("loc-b", "rule.two"), hit("loc-c", "rule.three")]), Session)
    with Session() as s:
        listing = queries.list_findings(s, state="all")
    assert listing["total"] == 1
    item = listing["items"][0]
    # Two of the three rules are listed as "also"; the third is the representative.
    assert len(item["also_flagged_by"]) == 2
    assert {item["rule_id"], *item["also_flagged_by"]} == {"rule.one", "rule.two", "rule.three"}


def test_history_endpoint_reports_earlier_findings_for_a_repository(Session):
    ingest(report("r1", findings=[finding("hist-1", 5, "CWE-79: x", "High", "fix", "fix failed", False, 3)]), Session)
    with Session() as s:
        items = queries.history_for(s, "o/r")
    assert items[0]["fingerprint"] == "hist-1"
    assert items[0]["fix_attempts"] == 3 and items[0]["fix_validated"] is False
    with Session() as s:
        assert queries.history_for(s, "other/repo") == []


def test_the_fix_trust_score_reaches_the_finding_detail(Session):
    f = finding("trust-1", 5, "CWE-79: x", "High", "fix", "fixed and validated", True, 1)
    f["fix"]["trust"], f["fix"]["review"] = 0.83, "uses a constant template"
    run = ingest(report("t1", findings=[f]), Session)
    with Session() as s:
        detail = queries.finding_detail(s, run.findings[0].id)
    assert detail["fix"]["trust"] == 0.83 and detail["fix"]["review"] == "uses a constant template"
