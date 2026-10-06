from unittest.mock import patch

from fixer import build_fix_prompt
from history import fetch_history, finding_history, history_note
from models import Finding
from triage import build_reasoning_prompt

REPO = "o/r"
RECORD = {
    "fingerprint": "x", "occurrences": 3, "first_seen": "2026-10-06T10:00:00+00:00",
    "last_seen": "2026-10-07T10:00:00+00:00", "llm_label": "tp", "laya_score": 0.83,
    "fix_attempts": 4, "fix_validated": False,
    "fix_failure": "still flagged", "fix_check_output": "AttributeError: hashlib",
    "last_proposal": "return hashlib.sha256(password)",
}


def finding():
    return Finding(file="app.py", line=98, rule_id="md5-used-as-password", cwe="CWE-327",
                   message="m", snippet="    return hashlib.md5(password.encode()).hexdigest()")


def test_note_states_facts_about_earlier_runs():
    note = history_note(RECORD)
    assert "reported by 3 earlier run(s)" in note
    assert "TRUE POSITIVE (Laya 0.83)" in note
    assert "did NOT pass validation" in note
    assert "AttributeError: hashlib" in note
    assert "do not repeat it" in note


def test_no_record_means_no_note():
    assert history_note(None) == ""


def test_triage_prompt_includes_history_only_when_given():
    assert "Earlier runs on this code" in build_reasoning_prompt(finding(), history="seen before")
    assert "Earlier runs" not in build_reasoning_prompt(finding())


def test_fix_prompt_tells_the_model_what_already_failed():
    prompt = build_fix_prompt(finding(), history="Earlier fix attempts (4) did NOT pass validation.")
    assert "Do not repeat an approach that already failed" in prompt
    assert "did NOT pass validation" in prompt


def test_finding_is_matched_by_repository_scoped_identity():
    f = finding()
    from identity import finding_fingerprint
    history = {finding_fingerprint(REPO, f.rule_id, f.file, f.snippet): RECORD}
    assert finding_history(history, REPO, f) is RECORD
    assert finding_history(history, "other/repo", f) is None


def test_unreachable_dashboard_means_no_history_not_a_failure():
    import urllib.error
    with patch("history.urllib.request.urlopen", side_effect=urllib.error.URLError("refused")):
        assert fetch_history("http://127.0.0.1:1", REPO) == {}


def test_no_dashboard_configured_means_no_history():
    assert fetch_history(None, REPO) == {}
    assert fetch_history("", REPO) == {}
