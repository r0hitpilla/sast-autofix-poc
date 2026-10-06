import os
import sys
from datetime import datetime

from git.exc import GitCommandError

from diff_utils import format_range
from git_utils import checkout_branch
from models import Hunk, TriageResult, ValidationResult


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

    for hunk in hunks:
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
    note = "re-scan clean" if validation.clean else "re-scan still flagged"
    if validation.test_output and validation.test_output != "no tests found":
        note += f"; tests: {validation.test_output[:500]}"
    else:
        note += f"; {validation.test_output}"
    return note


def build_pr_body(
    entries: list[tuple[TriageResult, ValidationResult]],
    hunks: list[Hunk] | None = None,
    repo_full_name: str | None = None,
    branch: str | None = None,
) -> str:
    validated_entries = [(t, v) for t, v in entries if v.validated]
    if not validated_entries:
        return "No validated findings in this run."

    per_entry, unassigned = assign_hunks(validated_entries, hunks or [])

    sections = ["## Automated security fixes\n"]

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


def run_id() -> str:
    """A per-run identifier: the Actions run id in CI, a timestamp locally."""
    return os.environ.get("GITHUB_RUN_ID") or datetime.now().strftime("%Y%m%d-%H%M%S")


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


def commit_validated_findings(repo, entries, strategy: str, run: str | None = None) -> list[str]:
    validated_entries = [(t, v) for t, v in entries if v.validated]
    branches = []

    if strategy == "single":
        # Unique per run: a fixed name makes every run after the first fail
        # to push (non-fast-forward against the previous run's branch).
        branch = f"autofix/run-{run or run_id()}"
        checkout_branch(repo, branch)
        for triage, _ in validated_entries:
            repo.git.add(triage.finding.file)
        _commit(repo, "fix: automated security fixes from sast-autofix-poc")
        branches = [branch] * len(validated_entries)
    else:  # per-finding
        seen = {}
        for triage, _ in validated_entries:
            finding = triage.finding
            file_slug = finding.file.rsplit("/", 1)[-1].replace(".", "-")
            base = f"autofix/{finding.rule_id.replace('.', '-')}-{file_slug}-L{finding.line}"
            # Same rule_id+file+line can recur (re-triaged finding, or two
            # closely related findings at the same line) — disambiguate
            # deterministically with an occurrence-index suffix so branch
            # names never collide within a batch.
            count = seen.get(base, 0)
            seen[base] = count + 1
            branch = base if count == 0 else f"{base}-{count}"

            checkout_branch(repo, branch)
            repo.git.add(finding.file)
            _commit(repo, f"fix: {finding.cwe} at {finding.file}:{finding.line}")
            branches.append(branch)

    return branches


def open_pr(
    github_client,
    repo_full_name: str,
    branch: str,
    title: str,
    body: str,
    dry_run: bool,
    line_comments: list[dict] | None = None,
):
    if dry_run:
        return None

    repo = github_client.get_repo(repo_full_name)
    pull = repo.create_pull(title=title, body=body, head=branch, base="main")

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


def open_autofix_prs(github_client, repo_full_name: str) -> list[str]:
    """URLs of autofix PRs still open — so automation doesn't stack new ones."""
    repo = github_client.get_repo(repo_full_name)
    return [
        pull.html_url for pull in repo.get_pulls(state="open")
        if pull.head.ref.startswith("autofix/")
    ]
