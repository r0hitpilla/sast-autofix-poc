from unittest.mock import MagicMock

from git.exc import GitCommandError

from git_utils import checkout_branch


def test_checkout_branch_creates_a_new_branch():
    repo = MagicMock()

    checkout_branch(repo, "autofix/x")

    repo.git.checkout.assert_called_once_with("-b", "autofix/x")


def test_checkout_branch_falls_back_to_plain_checkout_when_branch_exists():
    repo = MagicMock()
    repo.git.checkout.side_effect = [GitCommandError("git checkout -b", 128), None]

    checkout_branch(repo, "autofix/x")

    assert [c.args for c in repo.git.checkout.call_args_list] == [
        ("-b", "autofix/x"),
        ("autofix/x",),
    ]
