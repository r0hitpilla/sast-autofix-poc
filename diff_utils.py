"""Parse git's unified diff output into per-file changed-line hunks."""

import re

from models import Hunk

HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def parse_unified_diff(diff_text: str) -> list[Hunk]:
    hunks: list[Hunk] = []
    current_file = None
    current = None

    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            path = line[4:].strip()
            # "/dev/null" means the file was deleted; its hunks have no new side.
            current_file = path[2:] if path.startswith("b/") else path
            current = None
            continue
        if line.startswith("--- ") or line.startswith("diff --git"):
            current = None
            continue

        match = HUNK_HEADER_RE.match(line)
        if match:
            old_start, old_count, new_start, new_count = match.groups()
            current = Hunk(
                file=current_file,
                old_start=int(old_start),
                old_count=int(old_count) if old_count is not None else 1,
                new_start=int(new_start),
                new_count=int(new_count) if new_count is not None else 1,
            )
            hunks.append(current)
            continue

        if current is None:
            continue
        if line.startswith("-"):
            current.removed.append(line[1:])
        elif line.startswith("+"):
            current.added.append(line[1:])

    return hunks


def branch_hunks(repo, base: str, branch: str) -> list[Hunk]:
    """Every hunk a PR from `branch` into `base` would show, with zero context.

    `base...branch` (three dots) diffs against the merge base — exactly what
    GitHub's "Files changed" tab shows — so the line numbers here line up with
    the ones a reviewer sees in the PR.
    """
    return parse_unified_diff(
        repo.git.diff("-U0", "--no-color", f"{base}...{branch}")
    )


def format_range(start: int, count: int) -> str:
    if count == 0:
        return f"after L{start}"
    end = start + count - 1
    return f"L{start}" if end == start else f"L{start}–L{end}"
