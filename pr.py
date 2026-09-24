from models import TriageResult, ValidationResult


def build_pr_body(entries: list[tuple[TriageResult, ValidationResult]]) -> str:
    validated_entries = [(t, v) for t, v in entries if v.validated]
    if not validated_entries:
        return "No validated findings in this run."

    sections = ["## Automated security fixes\n"]
    for triage, validation in validated_entries:
        finding = triage.finding
        validation_note = (
            "re-scan clean" if validation.clean else "re-scan still flagged"
        )
        if validation.test_output and validation.test_output != "no tests found":
            validation_note += f"; tests: {validation.test_output[:500]}"
        else:
            validation_note += f"; {validation.test_output}"

        sections.append(
            f"### {finding.file}:{finding.line} — {finding.cwe}\n\n"
            f"**Original snippet:**\n```\n{finding.snippet}\n```\n\n"
            f"**Triage reasoning:** {triage.llm_reasoning}\n\n"
            f"**Laya confidence:** {triage.laya_score:.2f}\n\n"
            f"**Validated:** {validation_note}\n"
        )

    return "\n".join(sections)


def commit_validated_findings(repo, entries, strategy: str) -> list[str]:
    validated_entries = [(t, v) for t, v in entries if v.validated]
    branches = []

    if strategy == "single":
        branch = "autofix/all-validated-findings"
        repo.git.checkout("-b", branch)
        for triage, _ in validated_entries:
            repo.git.add(triage.finding.file)
        repo.git.commit("-m", "fix: automated security fixes from sast-autofix-poc")
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

            repo.git.checkout("-b", branch)
            repo.git.add(finding.file)
            repo.git.commit("-m", f"fix: {finding.cwe} at {finding.file}:{finding.line}")
            branches.append(branch)

    return branches


def open_pr(github_client, repo_full_name: str, branch: str, title: str, body: str, dry_run: bool):
    if dry_run:
        return None

    repo = github_client.get_repo(repo_full_name)
    pull = repo.create_pull(title=title, body=body, head=branch, base="main")
    return pull.html_url
