from diff_utils import parse_unified_diff
from models import Finding, Hunk, TriageResult, ValidationResult
from pr import assign_hunks, build_line_comments, build_pr_body

GIT_DIFF = """diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -44 +44,2 @@ def search_users():
-    query = f"SELECT id FROM users WHERE username = '{username}'"
+    query = "SELECT id FROM users WHERE username = ?"
+    rows = conn.execute(query, (username,)).fetchall()
@@ -54,0 +56,2 @@ def get_file(filename):
+    if not full_path.startswith(UPLOADS_DIR):
+        abort(403)
diff --git a/other.py b/other.py
--- a/other.py
+++ b/other.py
@@ -3 +2,0 @@
-import os
"""


def make_entry(line, cwe="CWE-89", validated=True):
    finding = Finding(
        file="app.py", line=line, rule_id=f"rule.{cwe}", cwe=cwe,
        message="m", snippet="s",
    )
    triage = TriageResult(
        finding=finding, llm_reasoning="why", laya_score=0.93, route="fix",
        evidence=[("Initial analysis", "why"), ("q", "a")],
    )
    validation = ValidationResult(
        finding=finding, clean=True, test_output="no tests found",
        validated=validated, attempts=2,
    )
    return triage, validation


def test_parse_unified_diff_extracts_line_ranges_per_file():
    hunks = parse_unified_diff(GIT_DIFF)

    assert [(h.file, h.old_start, h.old_count, h.new_start, h.new_count) for h in hunks] == [
        ("app.py", 44, 1, 44, 2),
        ("app.py", 54, 0, 56, 2),
        ("other.py", 3, 1, 2, 0),
    ]
    assert hunks[0].removed == ['    query = f"SELECT id FROM users WHERE username = \'{username}\'"']
    assert hunks[0].added[1] == "    rows = conn.execute(query, (username,)).fetchall()"


def test_assign_hunks_maps_each_hunk_to_nearest_finding_and_flags_strays():
    entries = [make_entry(44), make_entry(53, cwe="CWE-22")]
    per_entry, unassigned = assign_hunks(entries, parse_unified_diff(GIT_DIFF))

    assert [(h.new_start) for h in per_entry[0]] == [44]
    assert [(h.new_start) for h in per_entry[1]] == [56]
    assert [h.file for h in unassigned] == ["other.py"]


def test_pr_body_lists_exact_changed_lines_with_links():
    entries = [make_entry(44), make_entry(53, cwe="CWE-22")]
    body = build_pr_body(
        entries, parse_unified_diff(GIT_DIFF), "owner/repo", "autofix/all-validated-findings",
    )

    assert "| 1 | CWE-89 | `app.py` L44 |" in body
    assert (
        "[`app.py` L44–L45](https://github.com/owner/repo/blob/"
        "autofix/all-validated-findings/app.py#L44-L45)"
    ) in body
    assert "@@ app.py: was L44 → now L44–L45 @@" in body
    assert "@@ app.py: was after L54 → now L56–L57 @@" in body
    assert "+     if not full_path.startswith(UPLOADS_DIR):" in body
    # A change outside every finding is called out, never silently included.
    assert "Changes not tied to any finding" in body
    assert "other.py" in body
    assert "after 1 follow-up question(s)" in body


def test_line_comments_pin_to_every_changed_range():
    entries = [make_entry(44), make_entry(53, cwe="CWE-22")]
    comments = build_line_comments(entries, parse_unified_diff(GIT_DIFF))

    assert comments[0] | {"body": None} == {
        "path": "app.py", "side": "RIGHT", "start_line": 44, "start_side": "RIGHT",
        "line": 45, "body": None,
    }
    assert "CWE-89" in comments[0]["body"]
    assert comments[1]["line"] == 57 and comments[1]["start_line"] == 56
    assert "CWE-22" in comments[1]["body"]
    # Pure deletion: pinned to the removed line on the base side.
    assert comments[2]["path"] == "other.py"
    assert comments[2]["side"] == "LEFT" and comments[2]["line"] == 3
    assert "not tied to any finding" in comments[2]["body"]


def test_single_line_hunk_comment_has_no_start_line():
    hunk = Hunk(file="app.py", old_start=44, old_count=1, new_start=44, new_count=1, added=["x"])
    comments = build_line_comments([make_entry(44)], [hunk])
    assert comments == [comments[0]]
    assert "start_line" not in comments[0] and comments[0]["line"] == 44
