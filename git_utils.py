"""Small shared GitPython helpers used by both fixer.py and pr.py."""

from git.exc import GitCommandError


def checkout_branch(repo, branch: str) -> None:
    """Switch `repo` onto `branch`, creating it only if it doesn't exist yet.

    Idempotent on purpose: the same branch name is requested more than once
    in normal operation — `validator.validate_and_retry` re-calls
    `fixer.fix_finding` for the SAME finding on every retry (and
    `branch_name` is a pure function of the finding), and a second pipeline
    run against a target repo still carrying branches from a previous run
    asks for them again. A bare `checkout -b` raises GitCommandError in both
    cases and would take the whole pipeline down with it.
    """
    try:
        repo.git.checkout("-b", branch)
    except GitCommandError:
        repo.git.checkout(branch)
