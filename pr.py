import sys

from git.exc import GitCommandError

from diff_utils import format_range
from models import Hunk, TriageResult, ValidationResult
from triage import summarize_answer
from validator import tail


def assign_hunks(
    validated_entries: list[tuple[TriageResult, ValidationResult]],
    hunks: list[Hunk],
) -> tuple[list[list[Hunk]], list[Hunk]]:
    """Attribute each changed hunk to the validated finding it fixes.

    A hunk goes to the finding in the same file whose flagged line is nearest
    the hunk's base-side range. Returns one hunk list per entry (aligned with
    `validated_entries`) plus the hunks no finding accounts for — those are
    changes the model made outside any finding's file and must be surfaced,
    not hidden.
    """
    per_entry: list[list[Hunk]] = [[] for _ in validated_entries]
    unassigned: list[Hunk] = []

    def added_by(validation) -> set[str]:
        return {
            line[1:].strip() for line in (validation.fix_diff or "").splitlines()
            if line.startswith("+") and not line.startswith("+++") and line[1:].strip()
        }

    added = [added_by(v) for _, v in validated_entries]

    for hunk in hunks:
        # First choice: the one fix whose own diff added these lines (an
        # import added at the top of the file belongs to the fix that needed
        # it, not to whichever finding happens to be nearest).
        wanted = {line.strip() for line in hunk.added if line.strip()}
        owners = [
            i for i, (t, _) in enumerate(validated_entries)
            if t.finding.file == hunk.file and wanted and wanted <= added[i]
        ]
        if len(owners) == 1:
            per_entry[owners[0]].append(hunk)
            continue
        best, best_distance = None, None
        for i, (triage, _) in enumerate(validated_entries):
            finding = triage.finding
            if finding.file != hunk.file:
                continue
            if hunk.old_start <= finding.line <= hunk.old_end:
                distance = 0
            else:
                distance = min(
                    abs(finding.line - hunk.old_start),
                    abs(finding.line - hunk.old_end),
                )
            if best_distance is None or distance < best_distance:
                best, best_distance = i, distance
        if best is None:
            unassigned.append(hunk)
        else:
            per_entry[best].append(hunk)

    return per_entry, unassigned


def line_link(repo_full_name: str | None, branch: str | None, hunk: Hunk) -> str:
    label = f"`{hunk.file}` {format_range(hunk.new_start, hunk.new_count)}"
    if not repo_full_name or not branch or hunk.new_count == 0:
        return label
    anchor = f"#L{hunk.new_start}"
    if hunk.new_count > 1:
        anchor += f"-L{hunk.new_end}"
    return f"[{label}](https://github.com/{repo_full_name}/blob/{branch}/{hunk.file}{anchor})"


def format_hunk(hunk: Hunk) -> str:
    header = (
        f"@@ {hunk.file}: was {format_range(hunk.old_start, hunk.old_count)}"
        f" → now {format_range(hunk.new_start, hunk.new_count)} @@"
    )
    body = [f"- {line}" for line in hunk.removed] + [f"+ {line}" for line in hunk.added]
    return "```diff\n" + "\n".join([header, *body]) + "\n```"


def _validation_note(validation: ValidationResult) -> str:
    if validation.note:
        return f"⚠️ {validation.note}"
    note = "re-scan clean" if validation.clean else "re-scan still flagged"
    if validation.test_output and validation.test_output != "no tests found":
        note += f"; tests: {tail(validation.test_output, 300)}"
    else:
        note += f"; {validation.test_output}"
    return note


def build_suggestions(unresolved) -> str:
    """Findings this run could not fix automatically, with what the LLM
    found and (where it tried) its last, unverified fix proposal.
    `unresolved` holds report.FindingRecord-like objects."""
    if not unresolved:
        return ""
    parts = [
        "## ⚠️ Findings not fixed automatically — suggestions\n",
        "These need a developer's decision before merging. The proposed "
        "changes below were **not** validated; treat them as starting points.\n",
    ]
    for n, record in enumerate(unresolved, start=1):
        triage, validation = record.triage, record.validation
        finding = triage.finding
        analysis = summarize_answer(triage.evidence[-1][1]) if triage.evidence else ""
        parts.append(
            f"### {n}. `{finding.file}:{finding.line}` — {finding.cwe}\n\n"
            f"**Status:** {record.outcome} · Laya {triage.laya_score:.2f}"
            + (f" · {validation.attempts} fix attempt(s)" if validation else "")
            + "\n\n"
            f"**Flagged code:**\n```\n{finding.snippet}\n```\n\n"
            + (f"**Analysis:** {analysis}\n\n" if analysis else "")
            + (
                f"**Why the auto-fix was rejected:**\n```\n{tail(validation.test_output, 800)}\n```\n\n"
                if validation and not validation.validated else ""
            )
            + (
                "<details><summary>Last proposed fix (unverified)</summary>\n\n"
                f"```\n{validation.last_proposal[:3000]}\n```\n\n</details>\n"
                if validation and validation.last_proposal else ""
            )
        )
    return "\n".join(parts)


def build_pr_body(
    entries: list[tuple[TriageResult, ValidationResult]],
    hunks: list[Hunk] | None = None,
    repo_full_name: str | None = None,
    branch: str | None = None,
    base: str | None = None,
    unresolved=None,
) -> str:
    validated_entries = [(t, v) for t, v in entries if v.validated]
    suggestions = build_suggestions(unresolved)
    if not validated_entries:
        return suggestions or "No validated findings in this run."

    per_entry, unassigned = assign_hunks(validated_entries, hunks or [])

    sections = ["## Automated security fixes\n"]
    if base and branch:
        sections.append(
            f"Security scan of the whole repository on `{base}`. Merge this PR "
            f"(`{branch}` → `{base}`) to take the validated fixes below, then "
            f"merge `{base}` to `main` as usual.\n"
        )

    if hunks is not None:
        sections.append(
            "### Changed lines\n\n"
            "| # | Finding | Flagged at | Changed in this PR | Laya | Fix attempts |\n"
            "|---|---|---|---|---|---|"
        )
        for n, ((triage, validation), entry_hunks) in enumerate(
            zip(validated_entries, per_entry), start=1
        ):
            finding = triage.finding
            changed = "<br>".join(
                line_link(repo_full_name, branch, h) for h in entry_hunks
            ) or "_no diff found_"
            sections.append(
                f"| {n} | {finding.cwe} | `{finding.file}` L{finding.line} | "
                f"{changed} | {triage.laya_score:.2f} | {validation.attempts} |"
            )
        sections.append("")

    for n, ((triage, validation), entry_hunks) in enumerate(
        zip(validated_entries, per_entry), start=1
    ):
        finding = triage.finding
        section = (
            f"### {n}. {finding.file}:{finding.line} — {finding.cwe}\n\n"
            f"**Rule:** `{finding.rule_id}`\n\n"
            f"**Original snippet:**\n```\n{finding.snippet}\n```\n\n"
        )
        if entry_hunks:
            section += "**Modified lines:**\n\n" + "\n\n".join(
                f"{line_link(repo_full_name, branch, h)}\n\n{format_hunk(h)}"
                for h in entry_hunks
            ) + "\n\n"
        follow_ups = max(len(triage.evidence) - 1, 0)
        section += (
            f"**Laya confidence:** {triage.laya_score:.2f} "
            f"(after {follow_ups} follow-up question(s) to the LLM)\n\n"
            "<details><summary>Triage reasoning</summary>\n\n"
            f"{triage.llm_reasoning}\n\n</details>\n\n"
            f"**Validated:** {_validation_note(validation)} "
            f"(attempt {validation.attempts})\n"
        )
        sections.append(section)

    if unassigned:
        sections.append(
            "### ⚠️ Changes not tied to any finding\n\n"
            "The model also changed these lines. Review them with extra care.\n\n"
            + "\n\n".join(
                f"{line_link(repo_full_name, branch, h)}\n\n{format_hunk(h)}"
                for h in unassigned
            )
        )

    if suggestions:
        sections.append(suggestions)

    return "\n".join(sections)


def build_line_comments(
    entries: list[tuple[TriageResult, ValidationResult]],
    hunks: list[Hunk],
) -> list[dict]:
    """One inline PR review comment pinned to every changed hunk."""
    validated_entries = [(t, v) for t, v in entries if v.validated]
    per_entry, unassigned = assign_hunks(validated_entries, hunks)

    owned = [
        (hunk, triage, validation)
        for (triage, validation), entry_hunks in zip(validated_entries, per_entry)
        for hunk in entry_hunks
    ] + [(hunk, None, None) for hunk in unassigned]

    comments = []
    for hunk, triage, validation in owned:
        if triage is None:
            body = (
                "⚠️ **sast-autofix:** this change is not tied to any "
                "finding. Review it with extra care."
            )
        else:
            finding = triage.finding
            body = (
                f"🔒 **sast-autofix:** fixes **{finding.cwe}** "
                f"(`{finding.rule_id}`), flagged at original line "
                f"{finding.line}.\n\n"
                f"Laya confidence {triage.laya_score:.2f} · "
                f"{_validation_note(validation)} · "
                f"fix attempt {validation.attempts}"
            )

        if hunk.new_count > 0:
            # Pin to the new (RIGHT) side: these are the lines the PR adds.
            comment = {"path": hunk.file, "body": body, "side": "RIGHT", "line": hunk.new_end}
            if hunk.new_count > 1:
                comment.update(start_line=hunk.new_start, start_side="RIGHT")
        else:
            # Pure deletion: there's no new line to pin to, so pin to the
            # removed lines on the base (LEFT) side.
            comment = {"path": hunk.file, "body": body, "side": "LEFT", "line": hunk.old_end}
            if hunk.old_count > 1:
                comment.update(start_line=hunk.old_start, start_side="LEFT")
        comments.append(comment)

    return comments


BOT_IDENTITY = {
    "GIT_AUTHOR_NAME": "sast-autofix[bot]",
    "GIT_AUTHOR_EMAIL": "sast-autofix@users.noreply.github.com",
    "GIT_COMMITTER_NAME": "sast-autofix[bot]",
    "GIT_COMMITTER_EMAIL": "sast-autofix@users.noreply.github.com",
}


def _commit(repo, message: str) -> None:
    """Commit as the repo's configured user, or as the bot if there is none
    (a fresh machine or container has no git identity and `git commit`
    would abort the whole run after every fix had already validated)."""
    try:
        repo.git.config("user.email")
        repo.git.commit("-m", message)
    except GitCommandError:
        with repo.git.custom_environment(**BOT_IDENTITY):
            repo.git.commit("-m", message)


def commit_validated_findings(repo, entries, fix_branch: str) -> str:
    """Commit every validated fix onto `fix_branch`, (re)created from the
    branch currently checked out (the developer's branch, e.g. SV).

    `-B` resets the branch if it already exists: SV-fix is regenerated from
    the latest SV on every scan, never stacked on a stale previous run.
    """
    validated_entries = [(t, v) for t, v in entries if v.validated]
    repo.git.checkout("-B", fix_branch)
    files = [t.finding.file for t, _ in validated_entries]
    files += [path for _, v in validated_entries for path in v.created_files]
    for file in dict.fromkeys(files):
        repo.git.add(file)
    _commit(repo, "fix: automated security fixes from sast-autofix-poc")
    return fix_branch


def open_or_update_pr(
    github_client,
    repo_full_name: str,
    head: str,
    base: str,
    title: str,
    body: str,
    line_comments: list[dict] | None = None,
) -> str:
    """One PR per developer branch: head SV-fix -> base SV. A re-scan after
    another push to SV updates that PR instead of opening a new one."""
    repo = github_client.get_repo(repo_full_name)
    owner = repo_full_name.split("/")[0]
    existing = list(repo.get_pulls(state="open", head=f"{owner}:{head}", base=base))
    if existing:
        pull = existing[0]
        pull.edit(title=title, body=body)
    else:
        pull = repo.create_pull(title=title, body=body, head=head, base=base)

    if line_comments:
        try:
            pull.create_review(
                commit=repo.get_commit(pull.head.sha),
                body="Inline notes on every line sast-autofix changed.",
                event="COMMENT",
                comments=line_comments,
            )
        except Exception as exc:
            # The PR itself exists and its body already lists every changed
            # line — a rejected review must not lose the PR URL.
            print(f"[pr warning: inline line comments failed: {exc}]", file=sys.stderr)

    return pull.html_url


STATUS_CONTEXT = "sast-autofix / fix-branch rescan"


def set_commit_status(
    github_client, repo_full_name: str, sha: str, state: str,
    description: str, target_url: str | None = None,
) -> None:
    """Attach a check to a commit (shown on any PR whose head it is)."""
    try:
        commit = github_client.get_repo(repo_full_name).get_commit(sha)
        kwargs = {"state": state, "description": description[:140], "context": STATUS_CONTEXT}
        if target_url:
            kwargs["target_url"] = target_url
        commit.create_status(**kwargs)
    except Exception as exc:
        # The PR and its body are already up; a missing status is cosmetic.
        print(f"[pr warning: could not set commit status: {exc}]", file=sys.stderr)
