"""A fix may create new files (e.g. a template) under strict limits, and
retries rotate between fix models."""
import os
from unittest.mock import MagicMock, patch

from fixer import fix_finding
from models import Finding, FixResult, ValidationResult
from validator import validate_and_retry

APP = 'from flask import Flask, render_template\n\ndef welcome(name):\n    return f"<h1>Hi, {name}!</h1>"\n'
REPLY = '''<<<<<<< ORIGINAL
    return f"<h1>Hi, {name}!</h1>"
=======
    return render_template("welcome.html", name=name)
>>>>>>> FIXED

<<<<<<< NEW FILE templates/welcome.html
<h1>Hi, {{ name }}!</h1>
>>>>>>> END FILE
'''


def finding():
    return Finding(file="app.py", line=4, rule_id="xss", cwe="CWE-79", message="m",
                   snippet='return f"<h1>Hi, {name}!</h1>"')


def repo_at(tmp_path):
    (tmp_path / "app.py").write_text(APP)
    repo = MagicMock()
    repo.working_tree_dir = str(tmp_path)
    return repo


def test_fix_can_create_a_template(tmp_path):
    repo = repo_at(tmp_path)
    ollama = MagicMock()
    ollama.generate.return_value = REPLY

    result = fix_finding(finding(), ollama, repo)

    assert result.applied is True
    assert result.created_files == ["templates/welcome.html"]
    assert (tmp_path / "templates" / "welcome.html").read_text() == "<h1>Hi, {{ name }}!</h1>\n"
    assert 'render_template("welcome.html"' in (tmp_path / "app.py").read_text()


def _reply_creating(path):
    return f"<<<<<<< NEW FILE {path}\nx\n>>>>>>> END FILE\n"


def test_new_file_may_not_overwrite_escape_or_touch_ci(tmp_path):
    for path, why in [("app.py", "already exists"),
                      ("../outside.txt", "outside the repository"),
                      (".github/workflows/x.yml", "CI/repository configuration")]:
        repo = repo_at(tmp_path)
        ollama = MagicMock()
        ollama.generate.return_value = _reply_creating(path)
        result = fix_finding(finding(), ollama, repo)
        assert result.applied is False, path
        assert why in result.error, path
    assert (tmp_path / "app.py").read_text() == APP
    assert not (tmp_path.parent / "outside.txt").exists()


def test_retry_removes_files_the_previous_attempt_created(tmp_path):
    repo = repo_at(tmp_path)
    (tmp_path / "templates").mkdir()
    (tmp_path / "templates" / "welcome.html").write_text("old attempt")
    ollama = MagicMock()
    ollama.generate.return_value = REPLY

    result = fix_finding(finding(), ollama, repo, retry_feedback="tests failed",
                         baseline=APP, cleanup=["templates/welcome.html"])

    assert result.applied is True  # would have failed "already exists" without cleanup


def test_retries_rotate_fix_models(tmp_path):
    f = finding()
    unusable = FixResult(finding=f, diff="", applied=False, branch="b", error="no blocks")
    repo = repo_at(tmp_path)

    with patch("validator.fix_finding", return_value=unusable) as mock_fix:
        validate_and_retry(unusable, MagicMock(), repo, str(tmp_path), [], max_retries=3,
                           fix_models=["model-a", "model-b"])

    assert [c.kwargs["model"] for c in mock_fix.call_args_list] == ["model-b", "model-a", "model-b"]


def test_rejected_fix_removes_its_created_files(tmp_path):
    f = finding()
    repo = repo_at(tmp_path)
    os.makedirs(tmp_path / "templates")
    (tmp_path / "templates" / "welcome.html").write_text("x")
    applied = FixResult(finding=f, diff="d", applied=True, branch="b", baseline=APP,
                        created_files=["templates/welcome.html"])

    with patch("validator.scan", return_value=[f]), \
         patch("validator.run_test_suite", return_value=(True, "ok")):
        result = validate_and_retry(applied, MagicMock(), repo, str(tmp_path), [], max_retries=0)

    assert result.validated is False
    assert not (tmp_path / "templates").exists()


def test_commit_includes_created_files():
    from models import TriageResult
    from pr import commit_validated_findings

    repo = MagicMock()
    v = ValidationResult(finding=finding(), clean=True, test_output="", validated=True,
                         created_files=["templates/welcome.html"])

    commit_validated_findings(repo, [(TriageResult(finding(), "r", 0.9, "fix"), v)], "SV2-fix")

    added = [c.args[0] for c in repo.git.add.call_args_list]
    assert added == ["app.py", "templates/welcome.html"]


def test_created_file_is_attributed_to_the_fix_that_created_it():
    from models import Hunk, TriageResult
    from pr import assign_hunks

    v = ValidationResult(finding=finding(), clean=True, test_output="", validated=True,
                         fix_diff="+<h1>Hi, {{ name }}!</h1>\n",
                         created_files=["templates/welcome.html"])
    hunk = Hunk("templates/welcome.html", 0, 0, 1, 1, added=["<h1>Hi, {{ name }}!</h1>"])

    per_entry, unassigned = assign_hunks([(TriageResult(finding(), "r", 0.9, "fix"), v)], [hunk])

    assert per_entry == [[hunk]] and unassigned == []


def test_fix_prompt_lists_the_projects_dependencies(tmp_path):
    repo = repo_at(tmp_path)
    (tmp_path / "requirements.txt").write_text("Flask>=3.0.0\n")
    ollama = MagicMock()
    ollama.generate.return_value = "no blocks"

    fix_finding(finding(), ollama, repo)

    assert "Flask>=3.0.0" in ollama.generate.call_args.args[0]
