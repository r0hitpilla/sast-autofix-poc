"""Secret and dependency scanners that run beside Semgrep.

- gitleaks (MIT) finds hard-coded secrets in the working tree.
- osv-scanner (Apache-2.0) finds known-vulnerable dependencies in manifests
  and lockfiles, using the OSV database.

Both are external binaries, so each run is a subprocess. A missing binary is
an error, not a silent skip: a pipeline that quietly stops scanning for
secrets is worse than one that stops.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import time

from models import Finding

SECRET_CWE = "CWE-798"  # Use of Hard-coded Credentials
DEPENDENCY_CWE = "CWE-1395"  # Dependency on Vulnerable Third-Party Component

# The matched value is never shown: reports and LLM prompts must not carry
# the secret itself.
REDACTED = "[REDACTED]"


def _require(binary: str) -> str:
    path = shutil.which(binary)
    if path is None:
        raise RuntimeError(f"{binary} is not installed or not on PATH")
    return path


def _read_line(target_repo: str, path: str, line: int) -> str:
    try:
        with open(os.path.join(target_repo, path)) as f:
            lines = f.read().splitlines()
    except OSError:
        return ""
    return lines[line - 1] if 0 < line <= len(lines) else ""


def _cvss_severity(score: float) -> str:
    """CVSS v3 qualitative bands."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


# ---------------------------------------------------------------- secrets


def parse_gitleaks_json(raw: str, target_repo: str | None = None) -> list[Finding]:
    """gitleaks writes a JSON array, or nothing when it finds no leaks."""
    if not raw.strip():
        return []
    findings = []
    for leak in json.loads(raw) or []:
        path = leak["File"]
        line = leak["StartLine"]
        # Redact the value in the line we show, so the report and the LLM
        # prompt never carry the secret itself.
        secret = leak.get("Secret", "")
        snippet = _read_line(target_repo, path, line) if target_repo else leak.get("Match", "")
        if secret:
            snippet = snippet.replace(secret, REDACTED)
        findings.append(Finding(
            file=path,
            line=line,
            rule_id=f"gitleaks.{leak['RuleID']}",
            cwe=SECRET_CWE,
            message=(
                f"Hard-coded secret ({leak.get('Description') or leak['RuleID']}). "
                "Move it out of the code and rotate it: a secret in the repository "
                "must be treated as already leaked."
            ),
            snippet=snippet,
            severity="High",
            end_line=leak.get("EndLine", line),
        ))
    return findings


def run_gitleaks(target_repo: str) -> list[Finding]:
    binary = _require("gitleaks")
    # --no-git scans the working tree, the same files Semgrep sees, so a
    # secret added but not yet committed is caught too.
    result = subprocess.run(
        [binary, "detect", "--no-git", "--source", ".", "--report-format", "json",
         "--report-path", "-", "--no-banner", "--exit-code", "0"],
        capture_output=True, text=True, cwd=target_repo,
    )
    if result.returncode != 0:
        raise RuntimeError(f"gitleaks failed (exit {result.returncode}): {result.stderr}")
    return parse_gitleaks_json(result.stdout, target_repo)


# ---------------------------------------------------------- dependencies


def _fixed_versions(vuln: dict, package: str) -> list[str]:
    """Versions that fix this advisory for this package, lowest first."""
    fixed = []
    for affected in vuln.get("affected", []):
        if affected.get("package", {}).get("name", "").lower() != package.lower():
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    fixed.append(event["fixed"])
    return sorted(set(fixed))


def _max_cvss(vuln_id: str, groups: list) -> float | None:
    for group in groups:
        if vuln_id in group.get("ids", []):
            try:
                return float(group.get("max_severity", ""))
            except ValueError:
                return None
    return None


def _manifest_line(target_repo: str, path: str, package: str) -> int:
    """First line of the manifest that names the package, else line 1."""
    pattern = re.compile(rf"^\s*{re.escape(package)}\b", re.IGNORECASE)
    try:
        with open(os.path.join(target_repo, path)) as f:
            for number, text in enumerate(f, start=1):
                if pattern.match(text):
                    return number
    except OSError:
        pass
    return 1


def parse_osv_json(raw: str, target_repo: str | None = None) -> list[Finding]:
    if not raw.strip():
        return []
    data = json.loads(raw)
    findings = []
    for result in data.get("results", []):
        path = os.path.relpath(result["source"]["path"], target_repo) if target_repo else result["source"]["path"]
        for entry in result.get("packages", []):
            package = entry["package"]
            name, version = package["name"], package["version"]
            groups = entry.get("groups", [])
            for vuln in entry.get("vulnerabilities", []):
                vuln_id = vuln["id"]
                fixed = _fixed_versions(vuln, name)
                cvss = _max_cvss(vuln_id, groups)
                severity = _cvss_severity(cvss) if cvss is not None else "High"
                if fixed:
                    remedy = f"fixed in {', '.join(fixed)}; raise the requirement to at least {fixed[-1]}"
                else:
                    remedy = "no fixed version is published; choose a maintained alternative"
                summary = (vuln.get("summary") or "").strip()
                line = _manifest_line(target_repo, path, name) if target_repo else 1
                findings.append(Finding(
                    file=path,
                    line=line,
                    rule_id=f"osv.{vuln_id}",
                    cwe=DEPENDENCY_CWE,
                    message=(
                        f"{name} {version} is affected by {vuln_id}"
                        f"{': ' + summary if summary else ''}. {remedy}."
                    ),
                    snippet=_read_line(target_repo, path, line) if target_repo else "",
                    severity=severity,
                    end_line=line,
                    cvss=cvss,
                ))
    return findings


# Files whose content decides what osv-scanner finds. While none of them changes,
# the answer can't change either (within a run), so it is not asked for again.
MANIFEST_NAMES = {
    "pyproject.toml", "Pipfile.lock", "poetry.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "go.mod", "go.sum", "pom.xml", "Gemfile.lock", "Cargo.lock", "composer.lock",
}
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"}
OSV_RETRIES = (2, 5)   # seconds to wait before each retry of a failed run
_osv_cache: dict[str, tuple[str, list]] = {}


def manifest_fingerprint(target_repo: str) -> str:
    digest = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(target_repo):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if name in MANIFEST_NAMES or (name.startswith("requirements") and name.endswith((".txt", ".in"))):
                path = os.path.join(dirpath, name)
                digest.update(os.path.relpath(path, target_repo).encode())
                with open(path, "rb") as f:
                    digest.update(f.read())
    return digest.hexdigest()


def run_osv(target_repo: str) -> list[Finding]:
    """Dependency findings. osv-scanner asks api.osv.dev, so a network blip is
    retried, and the result is reused while the dependency files are unchanged:
    a fix to Python code can't change which dependencies are vulnerable."""
    binary = _require("osv-scanner")
    key = os.path.abspath(target_repo)
    fingerprint = manifest_fingerprint(target_repo)
    cached = _osv_cache.get(key)
    if cached and cached[0] == fingerprint:
        return list(cached[1])
    attempt = 0
    while True:
        result = subprocess.run(
            [binary, "scan", "source", "-r", ".", "--format", "json"],
            capture_output=True, text=True, cwd=target_repo,
        )
        # osv-scanner exits 1 when vulnerabilities are found, 128 when it found
        # no supported manifests. Only other codes are real failures.
        if result.returncode in (0, 1, 128):
            findings = parse_osv_json(result.stdout, target_repo)
            _osv_cache[key] = (fingerprint, findings)
            return list(findings)
        if attempt >= len(OSV_RETRIES):
            raise RuntimeError(f"osv-scanner failed (exit {result.returncode}) after {attempt + 1} attempts: "
                               f"{result.stderr[-600:]}")
        time.sleep(OSV_RETRIES[attempt])
        attempt += 1
