from identity import finding_fingerprint, normalise_code


def test_moving_the_line_does_not_change_identity():
    code = 'query = f"SELECT * FROM u WHERE n = {name}"'
    assert finding_fingerprint("o/r", "rule", "app.py", code) == finding_fingerprint("o/r", "rule", "app.py", code)


def test_whitespace_changes_do_not_change_identity():
    a = finding_fingerprint("o/r", "rule", "app.py", "return  redirect(next)")
    b = finding_fingerprint("o/r", "rule", "app.py", "return redirect(next)")
    assert a == b and normalise_code("  a\n\tb  ") == "a b"


def test_same_code_in_another_repository_is_a_different_finding():
    assert finding_fingerprint("o/a", "rule", "app.py", "x") != finding_fingerprint("o/b", "rule", "app.py", "x")


def test_separator_prevents_field_collisions():
    assert finding_fingerprint("o/r", "a|b", "c", "x") != finding_fingerprint("o/r", "a", "b|c", "x")


def test_pipeline_report_uses_the_same_identity():
    from models import Finding
    from report import fingerprint
    f = Finding(file="app.py", line=9, rule_id="rule", cwe="CWE-89", message="m", snippet="q  = 1")
    assert fingerprint(f, "o/r") == finding_fingerprint("o/r", "rule", "app.py", "q = 1")
