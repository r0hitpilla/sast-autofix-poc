import json
import subprocess

from models import Finding


def parse_semgrep_json(raw_json: str) -> list[Finding]:
    data = json.loads(raw_json)
    findings = []
    for result in data.get("results", []):
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})
        cwe_list = metadata.get("cwe", [])
        cwe = cwe_list[0] if cwe_list else "unknown"

        findings.append(Finding(
            file=result["path"],
            line=result["start"]["line"],
            rule_id=result["check_id"],
            cwe=cwe,
            message=extra.get("message", ""),
            snippet=extra.get("lines", ""),
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
    return parse_semgrep_json(raw)
