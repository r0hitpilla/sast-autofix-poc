"""Proof of fix: an exploit test that fails before the fix and passes after.

"The tests still pass" only shows a fix broke nothing. This asks for more:
for each finding a model writes one pytest test that ATTACKS the vulnerable
code and asserts the safe outcome. It is kept only if it genuinely fails on
the vulnerable code (by an assertion, not by a typo). After the fix the same
test must pass.

    proven      failed on the vulnerable code, passes on the fix
    refuted     failed on the vulnerable code and STILL fails on the fix:
                the exploit still works
    unproven    no valid exploit test could be produced (or it errored on
                the fix), so no claim either way
    not_applicable   dependency and secret findings: the scanner is the proof

A proven test is committed with the fix as a regression test.

Safety. The test runs here, against code that really is vulnerable, so:
every generated test is vetted before it runs (no network, subprocess, eval,
destructive commands, scanner-suppression comments), it runs with no secrets
in its environment, a temporary HOME, a timeout that kills its process group
and CPU and file-size limits. Real isolation (a disposable container or VM
runner) is still the right production setup: namespaces are blocked on this
host, so this is the strongest boundary available without it.
"""

import ast
import os
import re
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from fix_guard import SUPPRESSION, capabilities, describe
from hallucination import unresolved_imports
from injection import FENCE_RULE, fence, suspicious
from llm_usage import tag
from playbooks import _PASSWORD_HINT, _WEAK_HASH, _cwe
from scanner import scan

MAX_TEST_CHARS = 6000
OUTPUT_CHARS = 1200
CPU_SECONDS = 60
FILE_BYTES = 50 * 1024 * 1024
EXAMPLE_CHARS = 1800
# Modules a test may use beyond the standard library and the project's own
# requirements: the test runner and Flask's own dependencies.
TEST_PLATFORM = "pytest\nwerkzeug\nmarkupsafe\njinja2\nitsdangerous\nclick\n"

# Things no exploit test needs. The payloads may only create a file called
# "pwned" inside pytest's tmp_path; anything that reaches further is refused.
FORBIDDEN_TEXT = re.compile(
    r"(\brm\s+-|\bmkfs|\bdd\s+if=|\bcurl\b|\bwget\b|\bnc\s+-|\bncat\b|/dev/tcp|\bbash\s+-|\bsh\s+-c|"
    r"\bchmod\b|\bchown\b|\bsudo\b|\bnohup\b|python\d?\s+-c|powershell|/etc/|/root/|/home/|~/|"
    r"\.ssh|id_rsa|\.\./\.\./\.\.|0\.0\.0\.0|169\.254\.)",
    re.IGNORECASE,
)

# The test file must be self-contained, so it defines the `client` fixture itself.
CLIENT_FIXTURE = '''
import pytest

import <the module the project's tests import the app from> as app_module   # copy from the example tests


@pytest.fixture
def client():
    # set up the data, tables and files the endpoint needs, exactly as the example tests do
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as c:
        yield c
'''

BUILTIN_FIXTURES = {"tmp_path", "tmp_path_factory", "tmpdir", "tmpdir_factory", "monkeypatch", "capsys", "capfd",
                    "capsysbinary", "capfdbinary", "caplog", "request", "recwarn", "pytestconfig"}

GENERAL_RULES = """\
- One self-contained test file. Define your own fixtures; do not rely on fixtures from other test files.
  (tests/conftest.py only puts the repository root on sys.path, so `import app` style imports work.)
- Assert the SAFE behaviour, so the test FAILS while the vulnerability exists and PASSES once it is fixed.
  It must fail through an `assert` statement, never through an exception: put the attack request in
  `try/except Exception` where a rejected request could raise, and then assert on what is left.
- Accept any reasonable safe outcome (an error status, an empty result, sanitised output). Do not
  assert one specific status code or message unless the attack makes only that one possible.
- Start with a CONTROL: an ordinary request that must succeed. Set up the data, tables or files the endpoint
  needs exactly as the project's own tests do (see the example). Without this a test can "pass" only because
  the endpoint was broken or its database was never created, which proves nothing.
- Keep it short: one test function, under 50 lines.
- Use harmless payloads only. The allowed side effects are creating a file named `pwned` inside pytest's
  `tmp_path`, and (path traversal only) a canary file beside the served directory that the test removes in a
  `finally`. No other commands, no network, no other paths.
- Do not import subprocess, socket, ctypes, pickle, or use eval, exec or os.system.
- Name the test function `test_proof_<short_description>`.
"""


@dataclass(frozen=True)
class ProofClass:
    key: str
    label: str
    guidance: str
    skeleton: str = ""               # the shape of a good test; the model adapts names and fixtures
    allow: frozenset = frozenset()   # risky capabilities this class's test may use


CLASSES = {c.key: c for c in (
    ProofClass("sql_injection", "SQL injection",
               "Send a SQL-injection payload through the vulnerable request parameter, for example the value "
               "`x' OR '1'='1`. Assert the safe outcome: no row is returned for an account that was not asked for "
               "(the result list is empty, since nobody has that literal name), or the request is rejected with a 4xx.",
               skeleton='\ndef test_proof_sql_injection(client):\n    # control: an ordinary request works and finds a record that really exists\n    ok = client.get("/<route>", query_string={"<param>": "<a value that exists>"})\n    assert ok.status_code == 200 and ok.get_json()["<results key>"]\n    # attack: a condition that is always true\n    try:\n        rows = client.get("/<route>", query_string={"<param>": "nobody\' OR \'1\'=\'1"}).get_json()["<results key>"]\n    except Exception:\n        rows = []\n    assert rows == []        # a safe query finds nobody with that literal name\n'),
    ProofClass("xss", "cross-site scripting / template injection",
               "Request the vulnerable endpoint with the payload `<script>alert(1)</script>` and, separately, "
               "`{{1337*3}}`. Assert that the response body does NOT contain the raw `<script>alert(1)</script>` "
               "(escaped output such as `&lt;script&gt;` is fine) and does NOT contain `4011`, which would show "
               "the template engine evaluated the expression.",
               skeleton='\ndef test_proof_script_is_not_reflected(client):\n    assert client.get("/<route>", query_string={"<param>": "hello"}).status_code == 200      # control\n    try:\n        body = client.get("/<route>", query_string={"<param>": "<script>alert(1)</script>"}).get_data(as_text=True)\n        math = client.get("/<route>", query_string={"<param>": "{{1337*3}}"}).get_data(as_text=True)\n    except Exception:\n        body = math = ""\n    assert "<script>alert(1)</script>" not in body\n    assert "4011" not in math\n'),
    ProofClass("path_traversal", "path traversal",
               "Attack the project's REAL served directory; do not replace it with another one. Plant a canary file "
               "in the directory ABOVE the served directory (for example `os.path.join(os.path.dirname(served), "
               "'canary_secret.txt')` containing `TOP-SECRET-CANARY`), request it with `..%2Fcanary_secret.txt` "
               "(URL-encode the slash so the test client does not normalise the `..` away), and assert its "
               "contents are NOT in the response. Remove the canary afterwards, in a `finally`.",
               skeleton='\nimport os\n\n\ndef test_proof_path_traversal(client):\n    served = <the directory the endpoint serves from, e.g. the module\'s INVOICE_DIR; do NOT replace it>\n    # control: a file that really is in the served directory is served\n    assert client.get("/<route>/<name of a file that exists there>").status_code == 200\n    canary = os.path.join(os.path.dirname(served), "canary_secret.txt")\n    with open(canary, "w") as f:\n        f.write("TOP-SECRET-CANARY")\n    try:\n        try:\n            resp = client.get("/<route>/..%2Fcanary_secret.txt")\n            leaked = resp.status_code == 200 and b"TOP-SECRET-CANARY" in resp.data\n        except Exception:\n            leaked = False\n    finally:\n        os.remove(canary)\n    assert not leaked\n'),
    ProofClass("open_redirect", "open redirect",
               "Request the endpoint with the redirect target set to `https://evil.example/path`. Assert that the "
               "response does not redirect there: if there is a `Location` header it must not contain `evil.example`.",
               skeleton='\ndef test_proof_redirect_stays_on_site(client):\n    try:\n        resp = client.<get or post>("/<route>?<param>=https://evil.example/path", data={<any form fields the route needs>})\n        location = resp.headers.get("Location", "")\n    except Exception:\n        location = ""\n    assert "evil.example" not in location\n'),
    ProofClass("command_injection", "command injection",
               "Send a value containing a shell metacharacter that would create a canary file, for example "
               "`x; touch <tmp_path>/pwned #` (put the real `tmp_path` into the payload). End the payload with ` #` "
               "so the shell ignores whatever the application appends after your value (a file extension, more "
               "arguments); without it the injected `touch` often fails on those leftovers and the test would "
               "pass by accident. Assert the canary file does NOT exist afterwards. The only command allowed is "
               "`touch` on that canary.",
               skeleton='\ndef test_proof_command_injection(client, tmp_path):\n    canary = tmp_path / "pwned"\n    # control: an ordinary value works\n    assert client.get("/<route>", query_string={"<param>": "march"}).status_code == 200\n    try:\n        # the trailing " #" makes the shell ignore anything the application appends after the value\n        client.get("/<route>", query_string={"<param>": f"x; touch {canary} #"})\n    except Exception:\n        pass\n    assert not canary.exists()\n'),
    ProofClass("unsafe_yaml", "unsafe YAML deserialisation",
               "Send a YAML body that would run a harmless side effect if loaded unsafely: "
               "`!!python/object/apply:os.system [\"touch <tmp_path>/pwned\"]` (put the real `tmp_path` in). "
               "Assert the canary file does NOT exist afterwards. A safe loader raises, so catch exceptions.",
               skeleton='\ndef test_proof_unsafe_yaml(client, tmp_path):\n    canary = tmp_path / "pwned"\n    # control: an ordinary document is accepted\n    assert client.post("/<route>", data="<a normal document for this endpoint>", content_type="text/yaml").status_code == 200\n    evil = f\'!!python/object/apply:os.system ["touch {canary}"]\'\n    try:\n        client.post("/<route>", data=evil, content_type="text/yaml")\n    except Exception:\n        pass\n    assert not canary.exists()\n'),
    ProofClass("tls_verification", "disabled TLS certificate verification",
               "Use pytest's `monkeypatch` to replace the HTTP call the code makes (for example `requests.post`) with a "
               "fake that records its keyword arguments and returns a simple object with a `status_code`. Call the "
               "endpoint, then assert the recorded call did not pass `verify=False`: "
               "`assert kwargs.get('verify', True) is not False`.",
               skeleton='\ndef test_proof_tls_verification_is_not_disabled(client, monkeypatch):\n    calls = []\n\n    class Reply:\n        status_code = 200\n\n    def fake(*args, **kwargs):\n        calls.append(kwargs)\n        return Reply()\n\n    monkeypatch.setattr(requests, "<the function the code calls, e.g. post>", fake)\n    client.<get or post>("/<route>", json={})\n    assert calls, "the endpoint made no outgoing call"\n    assert all(kw.get("verify", True) is not False for kw in calls)\n',
               allow=frozenset({"module:requests"})),
    ProofClass("weak_password_hash", "weak password hashing",
               "Call the project's own password-hashing function with the same password twice and assert the two "
               "outputs differ (a unique salt per hash) and that neither equals `hashlib.md5(pw).hexdigest()` nor "
               "`hashlib.sha256(pw).hexdigest()`. Also assert that the project's check function accepts the right "
               "password and rejects a wrong one.",
               skeleton='\ndef test_proof_password_hash_is_salted():\n    import hashlib\n    import <module> as m\n    a, b = m.<hash function>("s3cret!"), m.<hash function>("s3cret!")\n    assert a != b            # a unique salt per hash\n    assert a != hashlib.md5(b"s3cret!").hexdigest() and a != hashlib.sha256(b"s3cret!").hexdigest()\n'),
)}


def classify(finding) -> ProofClass | None:
    """The kind of exploit test that fits this finding, or None when the scanner
    itself is the proof (dependencies, secrets) or the class isn't covered."""
    rule, cwe = finding.rule_id.lower(), _cwe(finding)
    code = f"{finding.snippet}\n{finding.message}".lower()
    if rule.startswith(("osv.", "gitleaks.")):
        return None
    if cwe == "CWE-601" or "open-redirect" in rule:
        return CLASSES["open_redirect"]
    if cwe == "CWE-89" or "sql-injection" in rule or "tainted-sql" in rule:
        return CLASSES["sql_injection"]
    if cwe == "CWE-78" or "subprocess" in rule or "command-injection" in rule:
        return CLASSES["command_injection"]
    if cwe == "CWE-502" and ("yaml" in rule or "yaml.load" in code):
        return CLASSES["unsafe_yaml"]
    if cwe in ("CWE-79", "CWE-96") or any(k in rule for k in ("render-template-string", "raw-html", "directly-returned-format-string")):
        return CLASSES["xss"]
    if cwe == "CWE-22" or "path-traversal" in rule:
        return CLASSES["path_traversal"]
    if cwe == "CWE-295" or ("cert" in rule and "valid" in rule):
        return CLASSES["tls_verification"]
    if (cwe == "CWE-916" or _PASSWORD_HINT.search(finding.snippet or "")) and _WEAK_HASH.search(code):
        return CLASSES["weak_password_hash"]
    return None


@dataclass
class ProofTest:
    path: str                    # repo-relative, e.g. tests/test_security_cwe89_orders_54.py
    code: str
    cls: str                     # ProofClass.key
    model: str
    attempts: int                # model attempts it took to get a valid failing test
    vulnerable_output: str       # why it fails on the vulnerable code
    mode: str = "advisory"
    timeout: int = 60
    outcome: str | None = None   # "passed" | "failed" | "error", from the latest check on a fix
    fixed_output: str = ""


# ---- the prompt ---------------------------------------------------------------

def pick_example_test(tests_dir: str, source_file: str) -> str | None:
    """The existing test file that exercises the code under test: named for it
    (orders.py -> test_orders.py), else one that imports it, else the first."""
    names = sorted(n for n in os.listdir(tests_dir) if n.startswith("test_") and n.endswith(".py")
                   and not n.startswith("test_security_"))
    stem = os.path.splitext(os.path.basename(source_file))[0]
    for name in names:
        if name == f"test_{stem}.py":
            return name
    imports = re.compile(rf"^\s*(import|from)\s+{re.escape(stem)}\b", re.MULTILINE)
    for name in names:
        if imports.search(open(os.path.join(tests_dir, name), errors="replace").read()):
            return name
    return names[0] if names else None


def test_examples(repo_dir: str, source_file: str = "") -> str:
    """How this project's tests are written, so the new test sets up its client and
    data the same way."""
    tests = os.path.join(repo_dir, "tests")
    parts = []
    conftest = os.path.join(tests, "conftest.py")
    if os.path.isfile(conftest):
        parts.append(f"# tests/conftest.py\n{open(conftest, errors='replace').read()[:EXAMPLE_CHARS // 2]}")
    name = pick_example_test(tests, source_file) if os.path.isdir(tests) else None
    if name:
        parts.append(f"# tests/{name} (start)\n{open(os.path.join(tests, name), errors='replace').read()[:EXAMPLE_CHARS]}")
    return "\n\n".join(parts)


def build_prompt(finding, cls: ProofClass, context: str, header: str, examples: str, feedback: str = "") -> str:
    prompt = (
        "You are a security engineer writing ONE pytest test that proves a vulnerability can be exploited, "
        "so that after a fix the same test proves it no longer can.\n\n"
        f"{FENCE_RULE}\n\n"
        f"Kind of weakness: {cls.label}\n"
        f"File: {finding.file}\nLine: {finding.line}\nCWE: {finding.cwe}\n"
        f"Scanner message: {' '.join(finding.message.split())[:300]}\n\n"
        f"The vulnerable code and its surroundings (line numbers are not part of the code):\n{fence(context or finding.snippet)}\n\n"
    )
    if header:
        prompt += f"The top of the file (its imports):\n{fence(header)}\n\n"
    if examples:
        prompt += f"How this project's existing tests are written:\n{fence(examples)}\n\n"
    prompt += f"What this test must do:\n{cls.guidance}\n\n"
    if "client" in cls.skeleton:
        prompt += ("Your file must DEFINE the `client` fixture itself; nothing else provides it. Use this, "
                   f"adapted to the project's example tests:\n```python\n{CLIENT_FIXTURE.strip()}\n```\n\n")
    if cls.skeleton:
        prompt += ("The shape of a good test. Copy this structure; replace everything in <angle brackets> and the "
                   f"fixtures with what THIS project's code and example tests use:\n```python\n{cls.skeleton.strip()}\n```\n\n")
    prompt += (
        f"Rules:\n{GENERAL_RULES}\n"
        "Reply with ONLY the Python source of the test file, in one ```python block."
    )
    if feedback:
        prompt += f"\n\nYour previous attempt was rejected: {feedback}\nWrite a corrected test."
    return prompt


def extract_code(reply: str) -> str:
    block = re.search(r"```(?:python|py)?\s*\n(.*?)```", reply or "", re.DOTALL)
    code = block.group(1) if block else (reply or "")
    return code.strip() + "\n" if code.strip() else ""


# ---- vetting what the model wrote -----------------------------------------------

def vet(code: str, repo_dir: str, allow=frozenset()) -> list[str]:
    """Reasons this test must not run. Empty means it may."""
    if not code.strip():
        return ["the reply contained no Python code"]
    if len(code) > MAX_TEST_CHARS:
        return [f"the test is too long ({len(code)} characters; keep it under {MAX_TEST_CHARS})"]
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return [f"the test has a syntax error: {exc.msg} (line {exc.lineno})"]
    problems = []
    tests = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name.startswith("test_")]
    if not tests:
        problems.append("it defines no function named test_...")
    if not any(isinstance(n, ast.Assert) for n in ast.walk(tree)):
        problems.append("it has no `assert`: it must assert the safe behaviour")
    defined = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and any(
        "fixture" in ast.dump(d) for d in n.decorator_list)}
    for fn in tests:
        missing = [a.arg for a in fn.args.args if a.arg not in BUILTIN_FIXTURES | defined]
        if missing:
            problems.append(f"{fn.name} uses the fixture {missing[0]!r}, which this file does not define "
                            "(define it with @pytest.fixture in the same file)")
    for cap in sorted(capabilities(code) - set(allow)):
        problems.append(f"it uses {describe(cap)}, which an exploit test does not need")
    if FORBIDDEN_TEXT.search(code):
        problems.append(f"it mentions something an exploit test must not touch ({FORBIDDEN_TEXT.search(code).group(0)!r})")
    if SUPPRESSION.search(code):
        problems.append("it contains a scanner-suppression comment")
    if suspicious(code):
        problems.append("it contains text aimed at an AI reviewer")
    requirements = ""
    req_path = os.path.join(repo_dir, "requirements.txt")
    if os.path.isfile(req_path):
        requirements = open(req_path, errors="replace").read()
    problems += unresolved_imports("tests/test_x.py", None, code, repo_dir, requirements + "\n" + TEST_PLATFORM)
    return problems


# ---- running a test, safely ---------------------------------------------------------

def _pytest_command(repo_dir: str) -> list[str]:
    """The project's own pytest when it has a .venv (where its dependencies live),
    else the one running this tool."""
    own = os.path.join(os.path.abspath(repo_dir), ".venv", "bin", "pytest")
    return [own] if os.path.exists(own) else [sys.executable, "-m", "pytest"]


def _limits() -> None:
    resource.setrlimit(resource.RLIMIT_CPU, (CPU_SECONDS, CPU_SECONDS))
    resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_BYTES, FILE_BYTES))
    os.setsid()  # own process group, so a timeout can kill everything it started


def scrubbed_env(home: str, repo_dir: str) -> dict:
    """No tokens, keys or credentials: the vulnerable code under test must not be
    able to read them out of its environment."""
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": home, "TMPDIR": home,
           "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": ""}
    venv = os.path.join(os.path.abspath(repo_dir), ".venv")
    if os.path.isdir(venv):
        env["VIRTUAL_ENV"] = venv
    return env


def classify_junit(xml_path: str, returncode: int) -> str:
    """"passed", "failed" (an assertion failed: the attack succeeded) or "error"
    (the test itself is broken). Only an assertion counts as the exploit working."""
    try:
        cases = list(ET.parse(xml_path).getroot().iter("testcase"))
    except (ET.ParseError, OSError):
        return "error"
    if not cases:
        return "error"
    outcomes = []
    for case in cases:
        bad = [c for c in case if c.tag in ("failure", "error")]
        if not bad:
            outcomes.append("passed")
        elif any(c.tag == "error" for c in bad):
            outcomes.append("error")
        else:
            message = (bad[0].get("message") or "").lstrip()
            outcomes.append("failed" if message.startswith(("assert", "AssertionError")) else "error")
    if "error" in outcomes:
        return "error"
    return "failed" if "failed" in outcomes else ("passed" if returncode == 0 else "error")


def error_summary(output: str, limit: int = 600) -> str:
    """The lines that say what went wrong ("E   fixture 'client' not found"), not
    the tail of pytest's output, which is usually a help tip."""
    lines = [line[1:].strip() for line in (output or "").splitlines() if line.startswith("E ")]
    text = "\n".join(lines[:8]) or (output or "")[-limit:]
    return text[:limit]


def run_test(repo_dir: str, rel_path: str, timeout: int = 60) -> tuple[str, str]:
    """Run one test file. Returns (outcome, short output)."""
    with tempfile.TemporaryDirectory(prefix="proof-") as home:
        xml_path = os.path.join(home, "result.xml")
        cmd = [*_pytest_command(repo_dir), rel_path, "-q", "--tb=short", "-p", "no:cacheprovider",
               f"--junitxml={xml_path}", "--basetemp", os.path.join(home, "tmp")]
        try:
            proc = subprocess.Popen(cmd, cwd=repo_dir, env=scrubbed_env(home, repo_dir), text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, preexec_fn=_limits)
        except OSError as exc:
            return "error", f"could not start pytest: {exc}"
        try:
            output, _ = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.communicate()
            return "error", f"the test did not finish within {timeout}s"
        return classify_junit(xml_path, proc.returncode), (output or "")[-OUTPUT_CHARS:]


# ---- preparing, checking and finishing a proof -------------------------------------------

def _slug(finding) -> str:
    stem = os.path.splitext(os.path.basename(finding.file))[0]
    cwe = re.sub(r"[^a-z0-9]", "", _cwe(finding).lower()) or "finding"
    return f"{cwe}_{re.sub(r'[^a-z0-9]+', '_', stem.lower())}_{finding.line}"


def discard(repo_dir: str, proof: ProofTest | None) -> None:
    if proof is not None:
        try:
            os.remove(os.path.join(repo_dir, proof.path))
        except OSError:
            pass


def prepare(finding, ollama, repo_dir: str, models: list[str], *, context: str = "", header: str = "",
            attempts: int = 3, timeout: int = 60, mode: str = "advisory", rulesets=(), engines=("semgrep",)):
    """Produce an exploit test that fails on the code as it stands now.

    Returns (ProofTest, "ready", "") or (None, status, reason) where status is
    "not_applicable" or "unproven". The test file is left in tests/ when ready;
    finalize() removes it unless the fix is proven.
    """
    cls = classify(finding)
    if cls is None:
        return None, "not_applicable", "the scanner is the proof for this kind of finding"
    tests_dir = os.path.join(repo_dir, "tests")
    if not os.path.isdir(tests_dir):
        return None, "not_applicable", "the project has no tests directory to put a regression test in"

    rel = f"tests/test_security_{_slug(finding)}.py"
    examples = test_examples(repo_dir, finding.file)
    feedback, reason = "", "no attempt succeeded"
    for n in range(attempts):
        model = models[(n + (1 if len(models) > 1 else 0)) % len(models)] if models else None
        try:
            with tag(purpose="proof", ref=f"{finding.file}:{finding.line}"):
                reply = ollama.generate(build_prompt(finding, cls, context, header, examples, feedback),
                                        think=False, **({"model": model} if model else {}))
        except Exception as exc:
            feedback = reason = f"the model call failed ({str(exc)[:120]})"
            continue
        code = extract_code(reply)
        problems = vet(code, repo_dir, cls.allow)
        if problems:
            feedback = reason = "; ".join(problems)[:500]
            continue
        with open(os.path.join(repo_dir, rel), "w") as f:
            f.write(code)
        outcome, output = run_test(repo_dir, rel, timeout)
        if outcome == "passed":
            feedback = reason = ("the test PASSED on the vulnerable code, so it does not demonstrate the "
                                 "vulnerability; make the attack actually work and assert the safe outcome")
        elif outcome == "error":
            feedback = reason = f"the test could not run properly: {error_summary(output)}"
        else:
            own = [f for f in scan(repo_dir, rulesets, engines) if f.file == rel]
            if own:
                feedback = reason = ("the test file itself is flagged by the security scanner "
                                     f"({own[0].rule_id}); write it without that pattern")
            else:
                return (ProofTest(path=rel, code=code, cls=cls.key, model=model or "", attempts=n + 1,
                                  vulnerable_output=output, mode=mode, timeout=timeout), "ready", "")
        discard(repo_dir, ProofTest(path=rel, code=code, cls=cls.key, model="", attempts=0, vulnerable_output=""))
    return None, "unproven", f"no valid exploit test after {attempts} attempt(s): {reason}"[:400]


def finalize(proof: ProofTest | None, status: str, reason: str, validation, repo_dir: str) -> dict:
    """The final proof record for a finding, once its fix has been decided.

    A proven test stays, is committed with the fix and joins its diff. Any
    other test file is removed so it can't fail later runs.
    """
    from fix_review import file_diff  # imported here: fix_review imports models, proof must stay import-light

    base = {"status": status, "reason": reason, "mode": proof.mode if proof else None}
    if proof is None:
        return base
    record = {**base, "test": proof.path, "class": proof.cls, "model": proof.model, "attempts": proof.attempts,
              "vulnerable_output": proof.vulnerable_output[-OUTPUT_CHARS:], "fixed_output": proof.fixed_output[-OUTPUT_CHARS:]}
    if not validation.validated:
        discard(repo_dir, proof)
        return {**record, "status": "unproven", "reason": "no fix was accepted, so there is nothing to prove"}
    if proof.outcome == "passed":
        with open(os.path.join(repo_dir, proof.path)) as f:
            validation.fix_diff += file_diff(proof.path, "", f.read())
        validation.created_files.append(proof.path)
        return {**record, "status": "proven", "reason": "fails on the original code, passes with the fix",
                "code": proof.code}
    discard(repo_dir, proof)
    if proof.outcome == "failed":
        return {**record, "status": "refuted",
                "reason": "the exploit test still fails with this fix: the attack may still work"}
    return {**record, "status": "unproven", "reason": "the test could not run against the fixed code"}
