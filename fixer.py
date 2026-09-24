import os
import re
import sys
import tempfile

from git.exc import GitCommandError

from git_utils import checkout_branch
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
    path = None
    try:
        fd, path = tempfile.mkstemp(suffix=".diff")
        # newline="\n": on Windows, text mode would translate every "\n" to
        # "\r\n", and git apply then fails to match the LF context lines in
        # the working tree ("patch does not apply").
        # Trailing "\n": extract_diff strips the model's fenced block, which
        # eats the final newline, and git apply rejects a patch whose last
        # hunk line is unterminated ("corrupt patch at line N").
        if not diff_text.endswith("\n"):
            diff_text += "\n"
        with os.fdopen(fd, "w", newline="\n") as f:
            f.write(diff_text)
        repo.git.apply("--whitespace=fix", path)
        return True
    except Exception:
        return False
    finally:
        if path is not None:
            os.remove(path)


def fix_finding(finding: Finding, ollama, repo, retry_feedback: str | None = None) -> FixResult:
    branch = branch_name(finding)

    try:
        model_output = ollama.generate(build_fix_prompt(finding, retry_feedback))
    except Exception as exc:
        # Spec: an Ollama call failure must never take the pipeline down —
        # log it and report the finding as unfixed so run_pipeline can skip
        # it and carry on with the remaining findings.
        print(
            f"[fix error: ollama call failed for {finding.file}:{finding.line}: {exc}]",
            file=sys.stderr,
        )
        return FixResult(finding=finding, diff="", applied=False, branch=branch)

    diff = extract_diff(model_output)

    if not diff:
        return FixResult(finding=finding, diff="", applied=False, branch=branch)

    checkout_branch(repo, branch)

    if retry_feedback is not None:
        # This is a retry: the previous attempt's rejected edits are still
        # sitting uncommitted in the working tree (fix branches never
        # commit). The fresh diff was generated against the ORIGINAL
        # snippet, so it would hit a context mismatch against those edits.
        # Discard just this finding's file back to HEAD before re-applying.
        try:
            repo.git.checkout("--", finding.file)
        except GitCommandError as exc:
            print(
                f"[fix warning: could not restore {finding.file} before retry: {exc}]",
                file=sys.stderr,
            )

    applied = apply_diff(repo, diff)

    return FixResult(finding=finding, diff=diff, applied=applied, branch=branch)
