import json
import os
import subprocess

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
            rule_id=result["check_id"],
            cwe=cwe,
            message=extra.get("message", ""),
            snippet=snippet,
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


def scan(target_repo: str, rulesets: list[str]) -> list[Finding]:
    raw = run_semgrep(target_repo, rulesets)
    return parse_semgrep_json(raw, target_repo)
