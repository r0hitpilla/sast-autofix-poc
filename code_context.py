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
