import os
import re
import tempfile

from models import Finding, FixResult

DIFF_BLOCK_RE = re.compile(r"```(?:diff)?\n(.*?)```", re.DOTALL)


def branch_name(finding: Finding) -> str:
    cwe_slug = finding.cwe.split(":")[0].strip().lower().replace(" ", "-")
    line_slug = f"L{finding.line}"
    file_slug = finding.file.rsplit("/", 1)[-1].replace(".", "-")
    return f"autofix/{cwe_slug}-{file_slug}-{line_slug}"


def build_fix_prompt(finding: Finding, retry_feedback: str | None = None) -> str:
    prompt = (
        "You are a security engineer writing a minimal fix for a single "
        "static analysis finding. Produce ONLY a unified diff patch for "
        "just the vulnerable lines — do not rewrite the whole file, do not "
        "add unrelated changes, wrap the diff in a ```diff code block.\n\n"
        f"File: {finding.file}\n"
        f"Line: {finding.line}\n"
        f"CWE: {finding.cwe}\n"
        f"Issue: {finding.message}\n\n"
        f"Vulnerable code:\n{finding.snippet}\n"
    )
    if retry_feedback:
        prompt += (
            "\nA previous attempt at this fix failed validation with this "
            f"feedback — produce a corrected diff:\n{retry_feedback}\n"
        )
    return prompt


def extract_diff(model_output: str) -> str:
    match = DIFF_BLOCK_RE.search(model_output)
    return match.group(1).strip() if match else ""


def apply_diff(repo, diff_text: str) -> bool:
    fd, path = tempfile.mkstemp(suffix=".diff")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(diff_text)
        repo.git.apply("--whitespace=fix", path)
        return True
    except Exception:
        return False
    finally:
        os.remove(path)


def fix_finding(finding: Finding, ollama, repo, retry_feedback: str | None = None) -> FixResult:
    model_output = ollama.generate(build_fix_prompt(finding, retry_feedback))
    diff = extract_diff(model_output)
    branch = branch_name(finding)

    if not diff:
        return FixResult(finding=finding, diff="", applied=False, branch=branch)

    repo.git.checkout("-b", branch)
    applied = apply_diff(repo, diff)

    return FixResult(finding=finding, diff=diff, applied=applied, branch=branch)
