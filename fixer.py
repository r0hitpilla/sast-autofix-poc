import os
import re
import sys
import tempfile

from git.exc import GitCommandError

from code_context import dependency_summary, numbered_context, numbered_header
from git_utils import checkout_branch
from models import Finding, FixResult
from playbooks import guidance_for

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

Use a separate block for each separate place you change. If you need a new
import, add it next to the file's existing imports at the top (its own edit
block), never inside a function, and never re-import a name the file already
imports. Every name the new code uses must still be defined: do not delete
lines other code depends on.

If the right fix needs a NEW file (for example a template the code renders),
create it with a block in exactly this format (path relative to the
repository root, the file must not exist yet):

<<<<<<< NEW FILE templates/example.html
(the complete content of the new file)
>>>>>>> END FILE

Never reference a file that neither exists nor is created by your reply."""


def build_fix_prompt(
    finding: Finding, retry_feedback: str | None = None, context: str = "", header: str = "",
    dependencies: str = "",
    playbook: str = "",
    history: str = "",
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
    if header:
        prompt += (
            "\nTop of the file — its existing imports (the number before each "
            "'|' is the line number, not part of the code):\n"
            f"{header}\n"
        )
    if context:
        prompt += (
            "\nCurrent file contents around the finding (the number before "
            "each '|' is the line number, not part of the code):\n"
            f"{context}\n"
        )
    if dependencies:
        prompt += (
            "\nThe project's declared dependencies (plus the Python standard "
            "library) — use only these, don't add new packages:\n"
            f"{dependencies}\n"
        )
    if playbook:
        prompt += (
            "\nHow to fix this kind of finding correctly (follow it; a smaller "
            f"edit that only silences the scanner is not acceptable):\n{playbook}\n"
        )
    if history:
        prompt += (
            "\nEarlier runs on this exact code (facts). Do not repeat an approach "
            f"that already failed:\n{history}\n"
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


NEW_FILE_RE = re.compile(
    r"^<{5,9} ?NEW FILE:?[ \t]+(\S+)[^\n]*\n(.*?)^>{5,9} ?END FILE[^\n]*$",
    re.DOTALL | re.MULTILINE,
)
PROTECTED_NEW_FILE_PREFIXES = (".github/", ".git/")


def extract_new_files(model_output: str) -> list[tuple[str, str]]:
    return [(path.strip().strip("`"), body) for path, body in NEW_FILE_RE.findall(model_output)]


def new_file_problem(repo, path: str) -> str | None:
    """Why `path` may not be created, or None if it may.

    New files are allowed so a fix can, e.g., move an inline HTML string into
    an auto-escaping template. They are kept inside the repository, never
    overwrite anything, and never touch CI configuration.
    """
    root = os.path.realpath(repo.working_tree_dir)
    full = os.path.realpath(os.path.join(root, path))
    if os.path.isabs(path) or not full.startswith(root + os.sep):
        return f"{path} is outside the repository"
    rel = os.path.relpath(full, root)
    if rel.startswith(PROTECTED_NEW_FILE_PREFIXES):
        return f"{path}: CI/repository configuration can't be created by a fix"
    if os.path.exists(full):
        return f"{path} already exists; edit it with ORIGINAL/FIXED blocks instead"
    return None


def remove_created(repo, paths: list[str]) -> None:
    """Delete files an earlier attempt created (and any directories that
    are left empty), so a retry or a rejected fix leaves no trace."""
    root = repo.working_tree_dir
    for path in paths:
        full = os.path.join(root, path)
        try:
            os.remove(full)
            os.removedirs(os.path.dirname(full))
        except OSError:
            pass


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


def apply_edits(repo, file: str, edits: list[tuple[str, str]]) -> tuple[bool, str]:
    """All-or-nothing, like `git apply`: if any block fails to match, the
    file is left exactly as it was. Returns (applied, reason it didn't)."""
    content = read_file(repo, file)
    if content is None:
        return False, f"{file} could not be read"
    for n, (original, replacement) in enumerate(edits, start=1):
        updated = apply_edit(content, original, replacement)
        if updated is None:
            where = "appears more than once" if content.count(original) > 1 else "was not found"
            return False, (
                f"The ORIGINAL text of edit block {n} {where} in {file}. Copy "
                "the ORIGINAL lines exactly from the numbered file contents "
                "(without the line numbers), with enough lines to be unique:\n"
                f"{original.rstrip()[:500]}"
            )
        content = updated
    with open(os.path.join(repo.working_tree_dir, file), "w", newline="") as f:
        f.write(content)
    return True, ""


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
    model: str | None = None,
    cleanup: list[str] | None = None,
    history: str = "",
) -> FixResult:
    """`model` overrides the LLM for this attempt (retries can rotate
    models); `cleanup` lists files the previous attempt created."""
    branch = branch_name(finding)
    remove_created(repo, cleanup or [])

    if retry_feedback is not None:
        # This is a retry: the previous attempt's rejected edits are still
        # sitting uncommitted in the working tree (fix branches never
        # commit). Put the file back to its pre-fix state BEFORE prompting,
        # so the model sees — and diffs against — the code it must patch.
        restore_file(repo, finding.file, baseline)
    else:
        baseline = read_file(repo, finding.file)

    context = numbered_context(repo.working_tree_dir, finding)
    header = numbered_header(repo.working_tree_dir, finding.file)
    dependencies = dependency_summary(repo.working_tree_dir)

    try:
        extra = {"model": model} if model else {}
        model_output = ollama.generate(
            build_fix_prompt(
                finding, retry_feedback, context, header, dependencies,
                playbook=guidance_for(finding), history=history,
            ),
            think=False, **extra
        )
    except Exception as exc:
        # Spec: an Ollama call failure must never take the pipeline down —
        # log it and report the finding as unfixed so run_pipeline can skip
        # it and carry on with the remaining findings.
        print(
            f"[fix error: ollama call failed for {finding.file}:{finding.line}: {exc}]",
            file=sys.stderr,
        )
        return FixResult(
            finding=finding, diff="", applied=False, branch=branch, baseline=baseline,
            error=f"The previous attempt produced no answer ({exc}). Reply concisely "
                  "with only the edit blocks.",
        )

    # Edit blocks are the requested format: models reliably copy code but
    # routinely miscount unified-diff hunk headers ("corrupt patch"). A
    # fenced diff is still accepted as a fallback.
    edits = extract_edits(model_output)
    new_files = extract_new_files(model_output)
    if edits or new_files:
        diff = model_output[model_output.index("<<<<<<<"):].strip()
    else:
        diff = extract_diff(model_output)

    if not diff:
        print(
            f"[fix warning: no edit blocks in model reply for {finding.file}:"
            f"{finding.line}; reply began: {model_output[:300]!r}]",
            file=sys.stderr,
        )
        return FixResult(
            finding=finding, diff="", applied=False, branch=branch, baseline=baseline,
            error=(
                "Your reply contained no edit blocks. Reply with ONLY "
                "<<<<<<< ORIGINAL / ======= / >>>>>>> FIXED blocks, no prose "
                "and no code fences."
            ),
        )

    # Apply first, branch second: both apply paths are all-or-nothing, so a
    # fix that doesn't apply leaves the tree untouched — and the repo must
    # then stay where it was, not be stranded on a fresh fix branch that
    # every later finding would silently build on. Uncommitted edits carry
    # over to the branch on checkout.
    problems = [p for p in (new_file_problem(repo, path) for path, _ in new_files) if p]
    created = []
    if problems:
        applied, error = False, "Cannot create new file: " + "; ".join(problems)
    elif edits or new_files:
        applied, error = apply_edits(repo, finding.file, edits) if edits else (True, "")
        if applied:
            for path, body in new_files:
                full = os.path.join(repo.working_tree_dir, path)
                os.makedirs(os.path.dirname(full) or ".", exist_ok=True)
                with open(full, "w", newline="") as f:
                    f.write(body)
                created.append(path)
    else:
        applied = apply_diff(repo, diff)
        error = "" if applied else (
            "Your diff did not apply. Use ORIGINAL/FIXED edit blocks instead."
        )
    if applied:
        checkout_branch(repo, branch)

    return FixResult(
        finding=finding, diff=diff, applied=applied, branch=branch,
        baseline=baseline, error=error, created_files=created,
    )
