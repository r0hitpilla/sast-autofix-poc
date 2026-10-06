import os
import re
import sys
import tempfile

from git.exc import GitCommandError

from code_context import numbered_context
from git_utils import checkout_branch
from models import Finding, FixResult

DIFF_BLOCK_RE = re.compile(r"```(?:diff)?\n(.*?)```", re.DOTALL)


def branch_name(finding: Finding) -> str:
    cwe_slug = finding.cwe.split(":")[0].strip().lower().replace(" ", "-")
    line_slug = f"L{finding.line}"
    file_slug = finding.file.rsplit("/", 1)[-1].replace(".", "-")
    return f"autofix/{cwe_slug}-{file_slug}-{line_slug}"


def build_fix_prompt(
    finding: Finding, retry_feedback: str | None = None, context: str = ""
) -> str:
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
    if context:
        prompt += (
            "\nCurrent file contents around the finding (the number before "
            "each '|' is the line number, not part of the code — use these "
            "numbers for the @@ hunk header and copy context lines exactly):\n"
            f"{context}\n"
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


def read_file(repo, file: str) -> str | None:
    try:
        with open(os.path.join(repo.working_tree_dir, file), newline="") as f:
            return f.read()
    except OSError:
        return None


def restore_file(repo, file: str, baseline: str | None) -> None:
    """Undo this finding's uncommitted edits to `file`.

    Prefer the pre-fix snapshot: `git checkout -- file` would also throw away
    every earlier validated-but-uncommitted fix in the same file (all three
    sample_vuln_app findings live in app.py). HEAD is only the fallback when
    no snapshot could be taken.
    """
    if baseline is not None:
        with open(os.path.join(repo.working_tree_dir, file), "w", newline="") as f:
            f.write(baseline)
        return
    try:
        repo.git.checkout("--", file)
    except GitCommandError as exc:
        print(f"[fix warning: could not restore {file}: {exc}]", file=sys.stderr)


def fix_finding(
    finding: Finding,
    ollama,
    repo,
    retry_feedback: str | None = None,
    baseline: str | None = None,
) -> FixResult:
    branch = branch_name(finding)

    if retry_feedback is not None:
        # This is a retry: the previous attempt's rejected edits are still
        # sitting uncommitted in the working tree (fix branches never
        # commit). Put the file back to its pre-fix state BEFORE prompting,
        # so the model sees — and diffs against — the code it must patch.
        restore_file(repo, finding.file, baseline)
    else:
        baseline = read_file(repo, finding.file)

    context = numbered_context(repo.working_tree_dir, finding)

    try:
        model_output = ollama.generate(build_fix_prompt(finding, retry_feedback, context))
    except Exception as exc:
        # Spec: an Ollama call failure must never take the pipeline down —
        # log it and report the finding as unfixed so run_pipeline can skip
        # it and carry on with the remaining findings.
        print(
            f"[fix error: ollama call failed for {finding.file}:{finding.line}: {exc}]",
            file=sys.stderr,
        )
        return FixResult(
            finding=finding, diff="", applied=False, branch=branch, baseline=baseline
        )

    diff = extract_diff(model_output)

    if not diff:
        return FixResult(
            finding=finding, diff="", applied=False, branch=branch, baseline=baseline
        )

    checkout_branch(repo, branch)
    applied = apply_diff(repo, diff)

    return FixResult(
        finding=finding, diff=diff, applied=applied, branch=branch, baseline=baseline
    )
