import os

from models import Finding


def numbered_context(target_repo: str, finding: Finding, radius: int = 15) -> str:
    """The source around `finding`, each line prefixed with its 1-based number.

    Semgrep's snippet is only the matched line(s). The LLM needs the
    surrounding function both to judge exploitability and to emit a diff whose
    context lines and hunk header actually match the file on disk. Returns ""
    when the file can't be read, so callers fall back to the snippet alone.
    """
    try:
        with open(os.path.join(target_repo, finding.file)) as f:
            lines = f.read().splitlines()
    except OSError:
        return ""

    start = max(finding.line - radius, 1)
    end = min(finding.line + radius, len(lines))
    width = len(str(end))
    return "\n".join(
        f"{n:>{width}} | {lines[n - 1]}" for n in range(start, end + 1)
    )


IMPORT_PREFIXES = ("import ", "from ")


def numbered_header(target_repo: str, file: str, max_lines: int = 40) -> str:
    """The file's import block, numbered like `numbered_context`.

    The fix prompt asks for new imports next to the existing ones; without
    seeing them the model guesses the import line, and an edit whose
    ORIGINAL text is a guess never matches the file. Returns "" when the
    file has no top-of-file imports or can't be read.
    """
    try:
        with open(os.path.join(target_repo, file)) as f:
            lines = f.read().splitlines()
    except OSError:
        return ""
    last = 0
    for n, line in enumerate(lines[:max_lines], start=1):
        if line.startswith(IMPORT_PREFIXES):
            last = n
    if not last:
        return ""
    width = len(str(last))
    return "\n".join(f"{n:>{width}} | {lines[n - 1]}" for n in range(1, last + 1))
