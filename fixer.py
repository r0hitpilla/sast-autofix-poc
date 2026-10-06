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


EDIT_FORMAT = """Reply with one or more edit blocks in exactly this format and nothing else:

<<<<<<< ORIGINAL
(lines copied EXACTLY from the current file, including indentation —
without the line-number prefix — just enough to be unique)
=======
(the replacement lines)
>>>>>>> FIXED

Use a separate block for each separate place you change (for example, one for
an import you add and one for the vulnerable code). Every name the new code
uses must still be defined: do not delete lines other code depends on."""


def build_fix_prompt(
    finding: Finding, retry_feedback: str | None = None, context: str = ""
) -> str:
    prompt = (
        "You are a security engineer writing a minimal, correct fix for a "
        "single static analysis finding. Change only what is needed to "
        "remove the vulnerability while keeping the code's behaviour for "
        "legitimate input.\n\n"
        f"File: {finding.file}\n"
        f"Line: {finding.line}\n"
        f"CWE: {finding.cwe}\n"
        f"Issue: {finding.message}\n\n"
        f"Vulnerable code:\n{finding.snippet}\n"
    )
    if context:
        prompt += (
            "\nCurrent file contents around the finding (the number before "
            "each '|' is the line number, not part of the code):\n"
            f"{context}\n"
        )
    prompt += "\n" + EDIT_FORMAT + "\n"
    if retry_feedback:
        prompt += (
            "\nA previous attempt at this fix failed validation with this "
            f"feedback — produce corrected edit blocks:\n{retry_feedback}\n"
        )
    return prompt


EDIT_BLOCK_RE = re.compile(
    r"^<{5,9} ?ORIGINAL[^\n]*\n(.*?)^={5,9}[^\n]*\n(.*?)^>{5,9}[^\n]*$",
    re.DOTALL | re.MULTILINE,
)


def extract_edits(model_output: str) -> list[tuple[str, str]]:
    return [(orig, new) for orig, new in EDIT_BLOCK_RE.findall(model_output) if orig.strip()]


def _indent(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def apply_edit(content: str, original: str, replacement: str) -> str | None:
    """Replace the single occurrence of `original` in `content`.

    Exact match first; failing that, match line by line ignoring
    surrounding whitespace (models often drop or shift indentation) and
    re-indent the replacement to where the match really is. Returns None when
    `original` is missing or ambiguous — never guesses between two places.
    """
    if content.count(original) == 1:
        return content.replace(original, replacement, 1)
    if content.count(original) > 1:
        return None

    lines = content.splitlines(keepends=True)
    want = [l.strip() for l in original.splitlines() if l.strip()]
    if not want:
        return None
    stripped = [l.strip() for l in lines]
    matches = []
    for i in range(len(lines)):
        j, k = i, 0
        while j < len(lines) and k < len(want):
            if not stripped[j]:  # tolerate blank-line differences
                j += 1
                continue
            if stripped[j] != want[k]:
                break
            j, k = j + 1, k + 1
        if k == len(want) and stripped[i]:
            matches.append((i, j))
    if len(matches) != 1:
        return None

    start, end = matches[0]
    file_indent = _indent(lines[start])
    rep_lines = replacement.splitlines()
    first = next((l for l in rep_lines if l.strip()), "")
    model_indent = _indent(first)
    reindented = [
        (file_indent + l[len(model_indent):] if l.startswith(model_indent) else file_indent + l.lstrip())
        if l.strip() else ""
        for l in rep_lines
    ]
    newline = "\n" if not lines[end - 1].endswith("\r\n") else "\r\n"
    text = newline.join(reindented) + (newline if reindented else "")
    return "".join(lines[:start]) + text + "".join(lines[end:])


def apply_edits(repo, file: str, edits: list[tuple[str, str]]) -> bool:
    """All-or-nothing, like `git apply`: if any block fails to match, the
    file is left exactly as it was."""
    content = read_file(repo, file)
    if content is None:
        return False
    for original, replacement in edits:
        content = apply_edit(content, original, replacement)
        if content is None:
            return False
    with open(os.path.join(repo.working_tree_dir, file), "w", newline="") as f:
        f.write(content)
    return True


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

    # Edit blocks are the requested format: models reliably copy code but
    # routinely miscount unified-diff hunk headers ("corrupt patch"). A
    # fenced diff is still accepted as a fallback.
    edits = extract_edits(model_output)
    if edits:
        diff = model_output[model_output.index("<<<<<<<"):].strip()
    else:
        diff = extract_diff(model_output)

    if not diff:
        return FixResult(
            finding=finding, diff="", applied=False, branch=branch, baseline=baseline
        )

    # Apply first, branch second: both apply paths are all-or-nothing, so a
    # fix that doesn't apply leaves the tree untouched — and the repo must
    # then stay where it was, not be stranded on a fresh fix branch that
    # every later finding would silently build on. Uncommitted edits carry
    # over to the branch on checkout.
    applied = apply_edits(repo, finding.file, edits) if edits else apply_diff(repo, diff)
    if applied:
        checkout_branch(repo, branch)

    return FixResult(
        finding=finding, diff=diff, applied=applied, branch=branch, baseline=baseline
    )
