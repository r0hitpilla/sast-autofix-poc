import json
import os
import subprocess

import external_scanners
from models import Finding


# Semgrep's JSON replaces `extra.lines` with this placeholder unless you're
# logged in to the Semgrep platform.
REDACTED_LINES = "requires login"


def read_lines(target_repo: str | None, path: str, start: int, end: int) -> str | None:
    if target_repo is None:
        return None
    try:
        with open(os.path.join(target_repo, path)) as f:
            lines = f.read().splitlines()
    except OSError:
        return None
    return "\n".join(lines[start - 1:end])


def clean_rule_id(check_id: str) -> str:
    """Semgrep prefixes rules loaded from a local file with that file's
    dotted absolute path ("home.user.proj.rules.my-rule"); keep just the
    rule's own id so it reads well in reports and PRs."""
    marker = ".rules."
    if marker in check_id and check_id.startswith(("home.", "Users.", "tmp.", "root.")):
        return check_id.rsplit(marker, 1)[1]
    return check_id


LEVELS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
BASIC_SEVERITY = {"ERROR": "High", "WARNING": "Medium", "INFO": "Low"}


def severity_of(extra: dict) -> str:
    """Critical / High / Medium / Low from Semgrep's own risk model.

    Security rules carry `impact` and `likelihood` (LOW/MEDIUM/HIGH); their
    combination is the rule author's risk call. Rules without them fall back
    to Semgrep's basic ERROR/WARNING/INFO severity.
    """
    metadata = extra.get("metadata", {})
    impact = LEVELS.get(str(metadata.get("impact", "")).upper())
    likelihood = LEVELS.get(str(metadata.get("likelihood", "")).upper())
    if impact and likelihood:
        if impact == 3 and likelihood == 3:
            return "Critical"
        if impact == 3 or (impact == 2 and likelihood == 3):
            return "High"
        if impact == 2:
            return "Medium"
        return "Low"
    return BASIC_SEVERITY.get(str(extra.get("severity", "")).upper(), "Medium")


def parse_semgrep_json(raw_json: str, target_repo: str | None = None) -> list[Finding]:
    data = json.loads(raw_json)
    findings = []
    for result in data.get("results", []):
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})
        cwe_list = metadata.get("cwe", [])
        cwe = cwe_list[0] if cwe_list else "unknown"

        # Read the flagged lines from the file itself: Semgrep's own copy is
        # just "requires login" without a platform login, which would leave
        # the LLM and Laya judging a finding with no code at all.
        snippet = read_lines(
            target_repo, result["path"], result["start"]["line"],
            result.get("end", result["start"])["line"],
        )
        if snippet is None:
            snippet = extra.get("lines", "")

        findings.append(Finding(
            file=result["path"],
            line=result["start"]["line"],
            rule_id=clean_rule_id(result["check_id"]),
            cwe=cwe,
            message=extra.get("message", ""),
            snippet=snippet,
            severity=severity_of(extra),
            owasp=list(metadata.get("owasp", [])),
            end_line=result.get("end", result["start"])["line"],
        ))
    return findings


def run_semgrep(target_repo: str, rulesets: list[str]) -> str:
    cmd = ["semgrep", "--json", "--quiet"]
    for ruleset in rulesets:
        cmd += ["--config", ruleset]
    # Scan "." from inside the target repo rather than passing the repo path
    # as an argument: Semgrep reports paths relative to what it was given, so
    # this makes every Finding.file repo-root-relative (e.g. "app.py", not
    # "sample_vuln_app/app.py"). That is the same frame GitPython uses for a
    # `git.Repo(target_repo)`, so `repo.git.apply` / `add` / `checkout --`
    # agree with Finding.file by construction instead of double-prefixing it.
    cmd.append(".")

    result = subprocess.run(cmd, capture_output=True, text=True, cwd=target_repo)
    if result.returncode not in (0, 1):
        # semgrep exits 1 when findings exist; anything else is a real failure
        raise RuntimeError(
            f"semgrep failed (exit {result.returncode}): {result.stderr}"
        )
    return result.stdout


ENGINES = ("semgrep", "gitleaks", "osv")


def scan(target_repo: str, rulesets: list[str], engines=("semgrep",)) -> list[Finding]:
    """Findings from every engine named in `engines`.

    Semgrep is the default so callers that only want SAST keep working. The
    secret and dependency engines are opt-in via config.yaml `engines`.
    """
    unknown = set(engines) - set(ENGINES)
    if unknown:
        raise ValueError(f"unknown scanner engine(s): {sorted(unknown)}")
    findings = []
    if "semgrep" in engines:
        findings += parse_semgrep_json(run_semgrep(target_repo, rulesets), target_repo)
    if "gitleaks" in engines:
        findings += external_scanners.run_gitleaks(target_repo)
    if "osv" in engines:
        findings += external_scanners.run_osv(target_repo)
    return findings
