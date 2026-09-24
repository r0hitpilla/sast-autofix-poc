from unittest.mock import MagicMock, patch

from cli import build_parser


def test_pr_subcommand_has_dry_run_flag():
    parser = build_parser()
    args = parser.parse_args(["pr", "--target-repo", "x", "--dry-run"])
    assert args.dry_run is True


def test_run_subcommand_has_dry_run_flag():
    parser = build_parser()
    args = parser.parse_args(["run", "--target-repo", "x", "--dry-run"])
    assert args.dry_run is True


def test_run_subcommand_defaults_dry_run_false():
    parser = build_parser()
    args = parser.parse_args(["run", "--target-repo", "x"])
    assert args.dry_run is False
