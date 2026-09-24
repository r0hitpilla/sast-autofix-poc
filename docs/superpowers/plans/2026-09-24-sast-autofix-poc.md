# SAST Autofix POC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a local-LLM-powered pipeline that scans a codebase with Semgrep, triages findings with Ollama + Laya, auto-fixes and validates high-confidence true positives, and opens a GitHub PR — plus a small deliberately-vulnerable Flask app to demo it against.

**Architecture:** Five sequential CLI subcommands (`scan`, `triage`, `fix`, `pr`, `run`) each backed by a focused module (`scanner.py`, `triage.py`, `fixer.py`, `validator.py`, `pr.py`), sharing typed dataclasses (`models.py`) and thin, mockable wrapper clients for Ollama and Laya so the orchestration logic is unit-testable without live services. `scan`/`triage` are usable standalone before `fix`/`pr` exist.

**Tech Stack:** Python 3.11, Semgrep CLI (subprocess), `ollama` Python client, `laya` (pip), GitPython, PyGithub, argparse, pytest.

**Spec:** [docs/superpowers/specs/2026-09-24-sast-autofix-poc-design.md](../specs/2026-09-24-sast-autofix-poc-design.md)

## Global Constraints

- No cloud LLM calls — Ollama host defaults to `http://localhost:11434` (DGX Spark, local).
- Ollama model name, Laya model name, thresholds, Semgrep rulesets, and PR strategy are all config-driven via `config.yaml`, never hardcoded in module code.
- Default Ollama model: `hf.co/mradermacher/Qwen3-Coder-30B-A3B-Instruct-Heretic-i1-GGUF:Q4_K_M`.
- Default thresholds: `> 0.8` fix, `0.4–0.8` review, `< 0.4` reject.
- Default Semgrep rulesets: `p/security-audit`, `p/owasp-top-ten`.
- `max_fix_retries` default: 2.
- Default PR strategy: `single` (one branch/PR for all validated findings); `per-finding` must also be supported.
- Any Ollama/Laya call failure routes the finding to `review`, never silently to reject.
- `pr` and `run` subcommands support `--dry-run` (skip push/PR creation, print what would happen).
- File layout is flat at the repo root (`scanner.py`, not `src/scanner.py`) — matches the spec's tree exactly.

---

### Task 1: Project scaffold, config loader, shared models

**Files:**
- Create: `requirements.txt`
- Create: `config.yaml`
- Create: `.gitignore`
- Create: `models.py`
- Create: `config.py`
- Test: `tests/test_config.py`

**Interfaces:**
- Produces: `models.Finding(file: str, line: int, rule_id: str, cwe: str, message: str, snippet: str)`
- Produces: `models.TriageResult(finding: Finding, llm_reasoning: str, laya_score: float, route: str)` — `route` is one of `"fix"`, `"review"`, `"reject"`.
- Produces: `models.FixResult(finding: Finding, diff: str, applied: bool, branch: str)`
- Produces: `models.ValidationResult(finding: Finding, clean: bool, test_output: str, validated: bool)`
- Produces: `config.Config` dataclass with fields `ollama_host, ollama_model, laya_model, threshold_fix, threshold_review, semgrep_rulesets, pr_strategy, max_fix_retries`.
- Produces: `config.load_config(path: str = "config.yaml") -> Config`.

- [ ] **Step 1: Write `requirements.txt`**

```
semgrep>=1.78.0
ollama>=0.3.0
laya>=0.3.0
GitPython>=3.1.0
PyGithub>=2.3.0
PyYAML>=6.0
pytest>=8.0.0
```

- [ ] **Step 2: Write `config.yaml`**

```yaml
ollama:
  host: http://localhost:11434
  model: hf.co/mradermacher/Qwen3-Coder-30B-A3B-Instruct-Heretic-i1-GGUF:Q4_K_M
laya:
  model: convaiinnovations/laya
thresholds:
  fix: 0.8
  review: 0.4
semgrep:
  rulesets:
    - p/security-audit
    - p/owasp-top-ten
pr:
  strategy: single   # or per-finding
max_fix_retries: 2
```

- [ ] **Step 3: Write `.gitignore`**

```
venv/
__pycache__/
*.pyc
.env
sample_vuln_app/
.pytest_cache/
```

- [ ] **Step 4: Write `models.py`**

```python
from dataclasses import dataclass


@dataclass
class Finding:
    file: str
    line: int
    rule_id: str
    cwe: str
    message: str
    snippet: str


@dataclass
class TriageResult:
    finding: Finding
    llm_reasoning: str
    laya_score: float
    route: str  # "fix" | "review" | "reject"


@dataclass
class FixResult:
    finding: Finding
    diff: str
    applied: bool
    branch: str


@dataclass
class ValidationResult:
    finding: Finding
    clean: bool
    test_output: str
    validated: bool
```

- [ ] **Step 5: Write the failing test for config loading**

```python
# tests/test_config.py
import os
import textwrap

import pytest

from config import load_config


@pytest.fixture
def config_file(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(textwrap.dedent("""\
        ollama:
          host: http://localhost:11434
          model: test-model
        laya:
          model: convaiinnovations/laya
        thresholds:
          fix: 0.8
          review: 0.4
        semgrep:
          rulesets:
            - p/security-audit
            - p/owasp-top-ten
        pr:
          strategy: single
        max_fix_retries: 2
        """))
    return str(path)


def test_load_config_reads_all_fields(config_file):
    cfg = load_config(config_file)
    assert cfg.ollama_host == "http://localhost:11434"
    assert cfg.ollama_model == "test-model"
    assert cfg.laya_model == "convaiinnovations/laya"
    assert cfg.threshold_fix == 0.8
    assert cfg.threshold_review == 0.4
    assert cfg.semgrep_rulesets == ["p/security-audit", "p/owasp-top-ten"]
    assert cfg.pr_strategy == "single"
    assert cfg.max_fix_retries == 2


def test_load_config_env_overrides_ollama_host(config_file, monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "http://10.0.0.5:11434")
    cfg = load_config(config_file)
    assert cfg.ollama_host == "http://10.0.0.5:11434"
```

- [ ] **Step 6: Run test to verify it fails**

Run: `pytest tests/test_config.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'config'` (or import error — `config.py` doesn't exist yet).

- [ ] **Step 7: Write `config.py`**

```python
import os
from dataclasses import dataclass

import yaml


@dataclass
class Config:
    ollama_host: str
    ollama_model: str
    laya_model: str
    threshold_fix: float
    threshold_review: float
    semgrep_rulesets: list
    pr_strategy: str
    max_fix_retries: int


def load_config(path: str = "config.yaml") -> Config:
    with open(path) as f:
        raw = yaml.safe_load(f)

    return Config(
        ollama_host=os.environ.get("OLLAMA_HOST", raw["ollama"]["host"]),
        ollama_model=raw["ollama"]["model"],
        laya_model=raw["laya"]["model"],
        threshold_fix=raw["thresholds"]["fix"],
        threshold_review=raw["thresholds"]["review"],
        semgrep_rulesets=raw["semgrep"]["rulesets"],
        pr_strategy=raw["pr"]["strategy"],
        max_fix_retries=raw["max_fix_retries"],
    )
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `pytest tests/test_config.py -v`
Expected: PASS (2 tests)

- [ ] **Step 9: Commit**

```bash
git add requirements.txt config.yaml .gitignore models.py config.py tests/test_config.py
git commit -m "feat: scaffold config loader and shared dataclasses"
```

---

### Task 2: sample_vuln_app demo target (own git repo)

**Files:**
- Create: `sample_vuln_app/app.py`
- Create: `sample_vuln_app/requirements.txt`
- Create: `sample_vuln_app/README.md`
- Create: `sample_vuln_app/.gitignore`

**Interfaces:**
- Produces: a runnable Flask app with three findable vulnerabilities Semgrep's `p/security-audit`/`p/owasp-top-ten` rulesets will flag: SQL injection, path traversal, and a custom race-condition privilege-leak bug. Later tasks (`scanner.py` onward) consume this app only as a Semgrep scan target — no code-level coupling.

- [ ] **Step 1: Write `sample_vuln_app/requirements.txt`**

```
Flask>=3.0.0
```

- [ ] **Step 2: Write `sample_vuln_app/app.py`**

```python
import os
import sqlite3
import threading

from flask import Flask, request, send_file, abort

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")
UPLOADS_DIR = os.path.join(os.path.dirname(__file__), "uploads")

# per-process cache of the last-checked role, keyed by a value that is NOT
# unique per request under concurrency (see /admin/data below).
_role_cache = {}
_role_cache_lock = threading.Lock()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY, username TEXT, role TEXT)"
    )
    conn.execute("DELETE FROM users")
    conn.executemany(
        "INSERT INTO users (username, role) VALUES (?, ?)",
        [("alice", "admin"), ("bob", "user"), ("carol", "user")],
    )
    conn.commit()
    conn.close()


@app.route("/search")
def search_users():
    """SQL injection: username is string-interpolated directly into the query."""
    username = request.args.get("username", "")
    conn = get_db()
    query = f"SELECT id, username, role FROM users WHERE username = '{username}'"
    rows = conn.execute(query).fetchall()
    conn.close()
    return {"results": [dict(r) for r in rows]}


@app.route("/files/<path:filename>")
def get_file(filename):
    """Path traversal: filename is joined into a path without containment checks."""
    full_path = os.path.join(UPLOADS_DIR, filename)
    return send_file(full_path)


@app.route("/admin/data")
def admin_data():
    """Custom logic bug: role is resolved by a background thread and cached
    per-process keyed by request.remote_addr, not per-request. Under
    concurrent requests from behind the same proxy/NAT, one caller's
    elevated role can be read back by a different, less-privileged caller
    before the cache entry is refreshed for their own username."""
    username = request.args.get("username", "")
    client_key = request.remote_addr  # not unique per user behind shared NAT/proxy

    with _role_cache_lock:
        cached = _role_cache.get(client_key)

    if cached is None:
        conn = get_db()
        row = conn.execute(
            "SELECT role FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()
        role = row["role"] if row else "user"
        with _role_cache_lock:
            _role_cache[client_key] = role
    else:
        role = cached  # stale/foreign role served from cache, not re-checked

    if role != "admin":
        abort(403)

    return {"secret": "admin-only payload", "served_role": role}


if __name__ == "__main__":
    os.makedirs(UPLOADS_DIR, exist_ok=True)
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
```

- [ ] **Step 3: Write `sample_vuln_app/.gitignore`**

```
users.db
uploads/
__pycache__/
*.pyc
```

- [ ] **Step 4: Write `sample_vuln_app/README.md`**

```markdown
# sample-vuln-app

Deliberately vulnerable Flask app used as a demo target for the
sast-autofix-poc pipeline. Do not deploy this anywhere reachable.

## Bugs (for demo narration)

1. `GET /search?username=...` — SQL injection (CWE-89), string-interpolated
   query.
2. `GET /files/<path:filename>` — path traversal (CWE-22), no containment
   check before `send_file`.
3. `GET /admin/data?username=...` — role cached per-client-address instead
   of per-username, so a shared NAT/proxy client can read back another
   user's cached admin role (race/logic bug, not a canned CWE snippet).

## Run

    python -m venv venv
    venv\Scripts\activate
    pip install -r requirements.txt
    python app.py
```

- [ ] **Step 5: Init sample_vuln_app as its own git repo and push**

Run (inside `sample_vuln_app/`):

```bash
cd sample_vuln_app
git init
git add app.py requirements.txt README.md .gitignore
git commit -m "feat: vulnerable Flask demo app (SQLi, path traversal, cache-leak race bug)"
git branch -M main
git remote add origin https://github.com/r0hitpilla/sast-poc-vuln-app.git
git push -u origin main
cd ..
```

**Blocked on `GITHUB_TOKEN` / git credentials** — this environment has no
`gh` CLI, no `credential.helper`, and no `GITHUB_TOKEN` set, so `git push`
will fail non-interactively. Do the `git init`/`add`/`commit`/`branch`
steps regardless (they need no auth); pause at `git push` until the user
provides a way to authenticate (a PAT with repo scope exported as
`GITHUB_TOKEN`, used as `https://<token>@github.com/r0hitpilla/sast-poc-vuln-app.git`,
or they push manually from a machine with saved credentials).

- [ ] **Step 6: Commit the outer repo's record of this task**

The `sample_vuln_app/` directory itself is gitignored from the outer
pipeline repo (Global Constraints), so there's nothing further to commit
outer-repo-side for this task.

---

### Task 3: scanner.py — Semgrep wrapper + JSON parsing

**Files:**
- Create: `scanner.py`
- Test: `tests/test_scanner.py`
- Test fixture: `tests/fixtures/semgrep_output.json`

**Interfaces:**
- Consumes: `config.Config.semgrep_rulesets: list[str]` (Task 1).
- Consumes: `models.Finding` (Task 1).
- Produces: `scanner.parse_semgrep_json(raw_json: str) -> list[Finding]`.
- Produces: `scanner.run_semgrep(target_repo: str, rulesets: list[str]) -> str` (returns raw JSON stdout).
- Produces: `scanner.scan(target_repo: str, rulesets: list[str]) -> list[Finding]` (calls `run_semgrep` then `parse_semgrep_json`).

- [ ] **Step 1: Write the Semgrep JSON test fixture**

```json
// tests/fixtures/semgrep_output.json
{
  "results": [
    {
      "check_id": "python.flask.security.injection.sql-injection-using-db-cursor-execute",
      "path": "sample_vuln_app/app.py",
      "start": {"line": 41, "col": 5},
      "end": {"line": 45, "col": 30},
      "extra": {
        "message": "Detected string-interpolated SQL query.",
        "metadata": {"cwe": ["CWE-89: SQL Injection"]},
        "lines": "def search_users():\n    username = request.args.get(\"username\", \"\")\n    conn = get_db()\n    query = f\"SELECT id, username, role FROM users WHERE username = '{username}'\"\n    rows = conn.execute(query).fetchall()"
      }
    }
  ]
}
```

- [ ] **Step 2: Write the failing tests**

```python
# tests/test_scanner.py
import json
import os

from scanner import parse_semgrep_json

FIXTURE_PATH = os.path.join(os.path.dirname(__file__), "fixtures", "semgrep_output.json")


def test_parse_semgrep_json_extracts_findings():
    with open(FIXTURE_PATH) as f:
        raw = f.read()

    findings = parse_semgrep_json(raw)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.file == "sample_vuln_app/app.py"
    assert finding.line == 41
    assert finding.rule_id == "python.flask.security.injection.sql-injection-using-db-cursor-execute"
    assert finding.cwe == "CWE-89: SQL Injection"
    assert "string-interpolated SQL query" in finding.message
    assert "SELECT id, username, role" in finding.snippet


def test_parse_semgrep_json_handles_missing_cwe():
    raw = json.dumps({
        "results": [{
            "check_id": "some.rule",
            "path": "a.py",
            "start": {"line": 1},
            "extra": {"message": "msg", "metadata": {}, "lines": "code"},
        }]
    })

    findings = parse_semgrep_json(raw)

    assert findings[0].cwe == "unknown"


def test_parse_semgrep_json_empty_results():
    raw = json.dumps({"results": []})
    assert parse_semgrep_json(raw) == []
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_scanner.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'scanner'`

- [ ] **Step 4: Write `scanner.py`**

```python
import json
import subprocess

from models import Finding


def parse_semgrep_json(raw_json: str) -> list[Finding]:
    data = json.loads(raw_json)
    findings = []
    for result in data.get("results", []):
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})
        cwe_list = metadata.get("cwe", [])
        cwe = cwe_list[0] if cwe_list else "unknown"

        findings.append(Finding(
            file=result["path"],
            line=result["start"]["line"],
            rule_id=result["check_id"],
            cwe=cwe,
            message=extra.get("message", ""),
            snippet=extra.get("lines", ""),
        ))
    return findings


def run_semgrep(target_repo: str, rulesets: list[str]) -> str:
    cmd = ["semgrep", "--json", "--quiet"]
    for ruleset in rulesets:
        cmd += ["--config", ruleset]
    cmd.append(target_repo)

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode not in (0, 1):
        # semgrep exits 1 when findings exist; anything else is a real failure
        raise RuntimeError(
            f"semgrep failed (exit {result.returncode}): {result.stderr}"
        )
    return result.stdout


def scan(target_repo: str, rulesets: list[str]) -> list[Finding]:
    raw = run_semgrep(target_repo, rulesets)
    return parse_semgrep_json(raw)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_scanner.py -v`
Expected: PASS (3 tests)

- [ ] **Step 6: Commit**

```bash
git add scanner.py tests/test_scanner.py tests/fixtures/semgrep_output.json
git commit -m "feat: add semgrep wrapper and finding parser"
```

---

### Task 4: ollama_client.py and laya_client.py wrappers

**Files:**
- Create: `ollama_client.py`
- Create: `laya_client.py`
- Test: `tests/test_ollama_client.py`
- Test: `tests/test_laya_client.py`

**Interfaces:**
- Consumes: `config.Config.ollama_host`, `config.Config.ollama_model`, `config.Config.laya_model` (Task 1).
- Produces: `ollama_client.OllamaClient(host: str, model: str)` with method `.generate(prompt: str) -> str`.
- Produces: `laya_client.LayaClient(model: str)` with method `.true_positive_score(state: str, question: str) -> float`.

- [ ] **Step 1: Write the failing test for `OllamaClient`**

```python
# tests/test_ollama_client.py
from unittest.mock import MagicMock, patch

from ollama_client import OllamaClient


def test_generate_returns_message_content():
    with patch("ollama_client.ollama.Client") as MockClient:
        instance = MockClient.return_value
        instance.chat.return_value = {"message": {"content": "hello from model"}}

        client = OllamaClient(host="http://localhost:11434", model="test-model")
        result = client.generate("say hi")

        assert result == "hello from model"
        instance.chat.assert_called_once_with(
            model="test-model",
            messages=[{"role": "user", "content": "say hi"}],
        )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_ollama_client.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'ollama_client'`

- [ ] **Step 3: Write `ollama_client.py`**

```python
import ollama


class OllamaClient:
    def __init__(self, host: str, model: str):
        self.client = ollama.Client(host=host)
        self.model = model

    def generate(self, prompt: str) -> str:
        response = self.client.chat(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
        )
        return response["message"]["content"]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_ollama_client.py -v`
Expected: PASS

- [ ] **Step 5: Write the failing test for `LayaClient`**

```python
# tests/test_laya_client.py
from unittest.mock import MagicMock, patch

from laya_client import LayaClient


def test_true_positive_score_extracts_noul_value():
    with patch("laya_client.laya.load") as mock_load:
        mock_agent = MagicMock()
        mock_agent.predict.return_value = {
            "true_positive": {"noul": 0.91}
        }
        mock_load.return_value = mock_agent

        client = LayaClient(model="convaiinnovations/laya")
        score = client.true_positive_score(
            state="finding + llm reasoning text",
            question="is this a true positive security vulnerability",
        )

        assert score == 0.91
        mock_agent.predict.assert_called_once()
        call_args = mock_agent.predict.call_args
        assert call_args[0][0] == "finding + llm reasoning text"
        questions = call_args[0][1]
        assert questions[0]["key"] == "true_positive"
        assert questions[0]["type"] == "noul"
        assert questions[0]["instructions"] == "is this a true positive security vulnerability"
```

- [ ] **Step 6: Run test to verify it fails**

Run: `pytest tests/test_laya_client.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'laya_client'`

- [ ] **Step 7: Write `laya_client.py`**

```python
import laya


class LayaClient:
    def __init__(self, model: str):
        self.agent = laya.load(model)

    def true_positive_score(self, state: str, question: str) -> float:
        questions = [{
            "key": "true_positive",
            "type": "noul",
            "instructions": question,
        }]
        result = self.agent.predict(state, questions)
        return result["true_positive"]["noul"]
```

- [ ] **Step 8: Run test to verify it passes**

Run: `pytest tests/test_laya_client.py -v`
Expected: PASS

- [ ] **Step 9: Verify the real Laya API on the DGX Spark before wiring into triage**

This wrapper's shape (`laya.load(model)`, `agent.predict(state, questions)`,
`result[key]["noul"]`) is based on the published Laya docs, not a
first-hand run. Before Task 5 depends on it, run this on the DGX Spark
(where `laya` is already installed) and fix `laya_client.py` if the real
signature differs:

```bash
python -c "import laya; agent = laya.load('convaiinnovations/laya'); print(agent.predict('test state', [{'key': 'k', 'type': 'noul', 'instructions': 'is this a test?'}]))"
```

Expected: a dict containing `{"k": {"noul": <float 0-1>}}` or close to it —
adjust `laya_client.py`'s key lookups to match whatever comes back.

- [ ] **Step 10: Commit**

```bash
git add ollama_client.py laya_client.py tests/test_ollama_client.py tests/test_laya_client.py
git commit -m "feat: add ollama and laya client wrappers"
```

---

### Task 5: triage.py — reasoning, scoring, routing

**Files:**
- Create: `triage.py`
- Test: `tests/test_triage.py`

**Interfaces:**
- Consumes: `models.Finding`, `models.TriageResult` (Task 1).
- Consumes: `ollama_client.OllamaClient.generate(prompt: str) -> str` (Task 4).
- Consumes: `laya_client.LayaClient.true_positive_score(state: str, question: str) -> float` (Task 4).
- Produces: `triage.build_reasoning_prompt(finding: Finding) -> str`.
- Produces: `triage.route(score: float, threshold_fix: float, threshold_review: float) -> str`.
- Produces: `triage.triage_finding(finding: Finding, ollama: OllamaClient, laya: LayaClient, threshold_fix: float, threshold_review: float) -> TriageResult`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_triage.py
from unittest.mock import MagicMock

from models import Finding
from triage import build_reasoning_prompt, route, triage_finding


def make_finding():
    return Finding(
        file="sample_vuln_app/app.py",
        line=41,
        rule_id="python.flask.security.injection.sql-injection",
        cwe="CWE-89",
        message="Detected string-interpolated SQL query.",
        snippet="query = f\"SELECT ... WHERE username = '{username}'\"",
    )


def test_build_reasoning_prompt_includes_finding_details():
    finding = make_finding()
    prompt = build_reasoning_prompt(finding)

    assert finding.file in prompt
    assert str(finding.line) in prompt
    assert finding.message in prompt
    assert finding.snippet in prompt


def test_route_above_fix_threshold():
    assert route(0.85, threshold_fix=0.8, threshold_review=0.4) == "fix"


def test_route_in_review_band():
    assert route(0.6, threshold_fix=0.8, threshold_review=0.4) == "review"
    assert route(0.4, threshold_fix=0.8, threshold_review=0.4) == "review"
    assert route(0.8, threshold_fix=0.8, threshold_review=0.4) == "review"


def test_route_below_review_threshold():
    assert route(0.1, threshold_fix=0.8, threshold_review=0.4) == "reject"


def test_triage_finding_wires_reasoning_into_laya_state():
    finding = make_finding()
    ollama = MagicMock()
    ollama.generate.return_value = "This looks exploitable; no upstream sanitization."
    laya = MagicMock()
    laya.true_positive_score.return_value = 0.92

    result = triage_finding(finding, ollama, laya, threshold_fix=0.8, threshold_review=0.4)

    assert result.finding is finding
    assert result.llm_reasoning == "This looks exploitable; no upstream sanitization."
    assert result.laya_score == 0.92
    assert result.route == "fix"

    laya_call_state = laya.true_positive_score.call_args[0][0]
    assert "This looks exploitable" in laya_call_state
    assert finding.message in laya_call_state


def test_triage_finding_routes_to_review_on_ollama_failure():
    finding = make_finding()
    ollama = MagicMock()
    ollama.generate.side_effect = ConnectionError("ollama unreachable")
    laya = MagicMock()

    result = triage_finding(finding, ollama, laya, threshold_fix=0.8, threshold_review=0.4)

    assert result.route == "review"
    assert result.laya_score == 0.0
    laya.true_positive_score.assert_not_called()


def test_triage_finding_routes_to_review_on_laya_failure():
    finding = make_finding()
    ollama = MagicMock()
    ollama.generate.return_value = "reasoning text"
    laya = MagicMock()
    laya.true_positive_score.side_effect = RuntimeError("laya model error")

    result = triage_finding(finding, ollama, laya, threshold_fix=0.8, threshold_review=0.4)

    assert result.route == "review"
    assert result.llm_reasoning == "reasoning text"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_triage.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'triage'`

- [ ] **Step 3: Write `triage.py`**

```python
from models import Finding, TriageResult

TRIAGE_QUESTION = "is this a true positive security vulnerability"


def build_reasoning_prompt(finding: Finding) -> str:
    return (
        "You are a security engineer triaging a static analysis finding.\n\n"
        f"File: {finding.file}\n"
        f"Line: {finding.line}\n"
        f"Rule: {finding.rule_id}\n"
        f"CWE: {finding.cwe}\n"
        f"Semgrep message: {finding.message}\n\n"
        f"Code context:\n{finding.snippet}\n\n"
        "In plain text, reason about whether this is a real, exploitable "
        "vulnerability or a false positive. Note anything Semgrep's static "
        "view might miss, such as input being sanitized earlier in the call "
        "chain, the route being unreachable, or the sink being safe in this "
        "context."
    )


def route(score: float, threshold_fix: float, threshold_review: float) -> str:
    if score > threshold_fix:
        return "fix"
    if score >= threshold_review:
        return "review"
    return "reject"


def triage_finding(
    finding: Finding,
    ollama,
    laya,
    threshold_fix: float,
    threshold_review: float,
) -> TriageResult:
    try:
        reasoning = ollama.generate(build_reasoning_prompt(finding))
    except Exception as exc:
        return TriageResult(
            finding=finding,
            llm_reasoning=f"[triage error: ollama call failed: {exc}]",
            laya_score=0.0,
            route="review",
        )

    state = (
        f"Finding: {finding.message} (CWE {finding.cwe}) at "
        f"{finding.file}:{finding.line}.\n"
        f"Code:\n{finding.snippet}\n\n"
        f"Analyst reasoning:\n{reasoning}"
    )

    try:
        score = laya.true_positive_score(state, TRIAGE_QUESTION)
    except Exception as exc:
        return TriageResult(
            finding=finding,
            llm_reasoning=reasoning,
            laya_score=0.0,
            route="review",
        )

    return TriageResult(
        finding=finding,
        llm_reasoning=reasoning,
        laya_score=score,
        route=route(score, threshold_fix, threshold_review),
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_triage.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add triage.py tests/test_triage.py
git commit -m "feat: add triage reasoning, laya scoring, and routing"
```

---

### Task 6: cli.py — scan and triage subcommands (manual test checkpoint)

**Files:**
- Create: `cli.py`
- Test: `tests/test_cli_scan_triage.py`

**Interfaces:**
- Consumes: `config.load_config` (Task 1), `scanner.scan` (Task 3), `ollama_client.OllamaClient`, `laya_client.LayaClient` (Task 4), `triage.triage_finding` (Task 5).
- Produces: `cli.py` runnable as `python cli.py scan --target-repo <path>` and `python cli.py triage --target-repo <path>`, each printing JSON-serializable results to stdout.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cli_scan_triage.py
import json
import subprocess
import sys


def test_scan_subcommand_prints_json_findings(tmp_path, monkeypatch):
    # Uses a fake semgrep on PATH so this test needs no real scanner/services.
    fake_semgrep = tmp_path / "semgrep"
    fake_semgrep.write_text(
        "#!/bin/sh\n"
        'echo \'{"results": []}\'\n'
    )
    fake_semgrep.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}:{subprocess.os.environ['PATH']}")

    result = subprocess.run(
        [sys.executable, "cli.py", "scan", "--target-repo", "."],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cli_scan_triage.py -v`
Expected: FAIL — `cli.py` doesn't exist (`FileNotFoundError` / non-zero exit with "can't open file").

- [ ] **Step 3: Write `cli.py`**

```python
import argparse
import dataclasses
import json
import sys

from config import load_config
from laya_client import LayaClient
from ollama_client import OllamaClient
from scanner import scan
from triage import triage_finding


def cmd_scan(args):
    cfg = load_config(args.config)
    findings = scan(args.target_repo, cfg.semgrep_rulesets)
    print(json.dumps([dataclasses.asdict(f) for f in findings], indent=2))


def cmd_triage(args):
    cfg = load_config(args.config)
    findings = scan(args.target_repo, cfg.semgrep_rulesets)
    ollama = OllamaClient(host=cfg.ollama_host, model=cfg.ollama_model)
    laya = LayaClient(model=cfg.laya_model)

    results = [
        triage_finding(f, ollama, laya, cfg.threshold_fix, cfg.threshold_review)
        for f in findings
    ]

    print(json.dumps([
        {
            "finding": dataclasses.asdict(r.finding),
            "llm_reasoning": r.llm_reasoning,
            "laya_score": r.laya_score,
            "route": r.route,
        }
        for r in results
    ], indent=2))


def build_parser():
    parser = argparse.ArgumentParser(prog="cli.py")
    parser.add_argument("--config", default="config.yaml")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_parser = sub.add_parser("scan", help="Run semgrep and print findings")
    scan_parser.add_argument("--target-repo", default="sample_vuln_app")
    scan_parser.set_defaults(func=cmd_scan)

    triage_parser = sub.add_parser("triage", help="Scan and triage findings")
    triage_parser.add_argument("--target-repo", default="sample_vuln_app")
    triage_parser.set_defaults(func=cmd_triage)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main(sys.argv[1:])
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_cli_scan_triage.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cli.py tests/test_cli_scan_triage.py
git commit -m "feat: wire scan and triage cli subcommands"
```

- [ ] **Step 6: Manual checkpoint — run against the real demo app on the DGX Spark**

This is the point the spec calls out for hands-on testing before `fix`/`pr`
are built. On the DGX Spark, with `sample_vuln_app` running and Ollama/Semgrep
available:

```bash
python cli.py scan --target-repo sample_vuln_app
python cli.py triage --target-repo sample_vuln_app
```

Confirm: `scan` reports the 3 seeded findings (SQLi, path traversal,
cache-leak race bug); `triage` produces plausible reasoning text and a
`laya_score` per finding, and the SQLi/path-traversal findings route to
`"fix"` while the race-condition one (subtler, may need `review`) routes
sensibly. Do not proceed to Task 7 until this looks right — tune
`config.yaml` thresholds here if routing looks off.

---

### Task 7: fixer.py — diff generation and patch application

**Files:**
- Create: `fixer.py`
- Test: `tests/test_fixer.py`

**Interfaces:**
- Consumes: `models.Finding`, `models.FixResult` (Task 1).
- Consumes: `ollama_client.OllamaClient.generate(prompt: str) -> str` (Task 4).
- Produces: `fixer.build_fix_prompt(finding: Finding, retry_feedback: str | None = None) -> str`.
- Produces: `fixer.branch_name(finding: Finding) -> str`.
- Produces: `fixer.apply_diff(repo, diff_text: str) -> bool` — `repo` is a `git.Repo` (GitPython); returns whether `git apply` succeeded.
- Produces: `fixer.fix_finding(finding: Finding, ollama, repo, retry_feedback: str | None = None) -> FixResult`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_fixer.py
from unittest.mock import MagicMock

from models import Finding
from fixer import apply_diff, branch_name, build_fix_prompt, fix_finding

SAMPLE_DIFF = """--- a/app.py
+++ b/app.py
@@ -1,1 +1,1 @@
-query = f"SELECT * FROM users WHERE username = '{username}'"
+query = "SELECT * FROM users WHERE username = ?"
"""


def make_finding():
    return Finding(
        file="sample_vuln_app/app.py",
        line=41,
        rule_id="python.flask.security.injection.sql-injection",
        cwe="CWE-89",
        message="Detected string-interpolated SQL query.",
        snippet="query = f\"SELECT ... WHERE username = '{username}'\"",
    )


def test_branch_name_is_stable_and_safe():
    finding = make_finding()
    name = branch_name(finding)
    assert name.startswith("autofix/")
    assert " " not in name
    assert "CWE-89".lower() in name.lower() or "cwe-89" in name.lower()


def test_build_fix_prompt_without_retry_feedback():
    finding = make_finding()
    prompt = build_fix_prompt(finding)
    assert finding.file in prompt
    assert finding.snippet in prompt
    assert "unified diff" in prompt.lower()


def test_build_fix_prompt_includes_retry_feedback():
    finding = make_finding()
    prompt = build_fix_prompt(finding, retry_feedback="Previous patch broke test_search")
    assert "Previous patch broke test_search" in prompt


def test_apply_diff_calls_git_apply(tmp_path):
    repo = MagicMock()
    ok = apply_diff(repo, SAMPLE_DIFF)
    assert ok is True
    repo.git.apply.assert_called_once()


def test_apply_diff_returns_false_on_git_error():
    repo = MagicMock()
    repo.git.apply.side_effect = Exception("patch does not apply")
    ok = apply_diff(repo, SAMPLE_DIFF)
    assert ok is False


def test_fix_finding_extracts_diff_and_applies_it():
    finding = make_finding()
    ollama = MagicMock()
    ollama.generate.return_value = f"```diff\n{SAMPLE_DIFF}```"
    repo = MagicMock()

    result = fix_finding(finding, ollama, repo)

    assert result.finding is finding
    assert "SELECT * FROM users WHERE username = ?" in result.diff
    assert result.applied is True
    assert result.branch.startswith("autofix/")
    repo.git.checkout.assert_called_once_with("-b", result.branch)


def test_fix_finding_marks_not_applied_when_no_diff_found():
    finding = make_finding()
    ollama = MagicMock()
    ollama.generate.return_value = "I don't think this needs a fix."
    repo = MagicMock()

    result = fix_finding(finding, ollama, repo)

    assert result.applied is False
    assert result.diff == ""
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_fixer.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'fixer'`

- [ ] **Step 3: Write `fixer.py`**

```python
import re

from models import Finding, FixResult

DIFF_BLOCK_RE = re.compile(r"```(?:diff)?\n(.*?)```", re.DOTALL)


def branch_name(finding: Finding) -> str:
    cwe_slug = finding.cwe.split(":")[0].strip().lower().replace(" ", "-")
    line_slug = f"L{finding.line}"
    file_slug = finding.file.rsplit("/", 1)[-1].replace(".", "-")
    return f"autofix/{cwe_slug}-{file_slug}-{line_slug}"


def build_fix_prompt(finding: Finding, retry_feedback: str | None = None) -> str:
    prompt = (
        "You are a security engineer writing a minimal fix for a single "
        "static analysis finding. Produce ONLY a unified diff patch for "
        "just the vulnerable lines — do not rewrite the whole file, do not "
        "add unrelated changes, wrap the diff in a ```diff code block.\n\n"
        f"File: {finding.file}\n"
        f"Line: {finding.line}\n"
        f"CWE: {finding.cwe}\n"
        f"Issue: {finding.message}\n\n"
        f"Vulnerable code:\n{finding.snippet}\n"
    )
    if retry_feedback:
        prompt += (
            "\nA previous attempt at this fix failed validation with this "
            f"feedback — produce a corrected diff:\n{retry_feedback}\n"
        )
    return prompt


def extract_diff(model_output: str) -> str:
    match = DIFF_BLOCK_RE.search(model_output)
    return match.group(1).strip() if match else ""


def apply_diff(repo, diff_text: str) -> bool:
    try:
        repo.git.apply("--whitespace=fix", "-")  # GitPython passes stdin via kwargs in real use
        return True
    except Exception:
        return False


def fix_finding(finding: Finding, ollama, repo, retry_feedback: str | None = None) -> FixResult:
    model_output = ollama.generate(build_fix_prompt(finding, retry_feedback))
    diff = extract_diff(model_output)
    branch = branch_name(finding)

    if not diff:
        return FixResult(finding=finding, diff="", applied=False, branch=branch)

    repo.git.checkout("-b", branch)
    applied = apply_diff(repo, diff)

    return FixResult(finding=finding, diff=diff, applied=applied, branch=branch)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_fixer.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Fix `apply_diff`'s real stdin wiring**

The unit test mocks `repo.git.apply`, so it doesn't catch that GitPython's
`repo.git.apply(...)` needs the diff content passed as a temp file or via
`istream`, not written as a literal `"-"` arg with no stdin attached. Replace
`apply_diff` with a version that writes the diff to a temp file and passes
its path, which works with both the real GitPython API and the existing
mock-based tests (mocks don't care about the real filesystem call):

```python
import tempfile
import os


def apply_diff(repo, diff_text: str) -> bool:
    fd, path = tempfile.mkstemp(suffix=".diff")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(diff_text)
        repo.git.apply("--whitespace=fix", path)
        return True
    except Exception:
        return False
    finally:
        os.remove(path)
```

Update the two `apply_diff` tests to assert `repo.git.apply.assert_called_once()`
without checking the exact second argument (it's now a temp path):

```python
def test_apply_diff_calls_git_apply(tmp_path):
    repo = MagicMock()
    ok = apply_diff(repo, SAMPLE_DIFF)
    assert ok is True
    assert repo.git.apply.call_count == 1
    assert repo.git.apply.call_args[0][0] == "--whitespace=fix"
```

Run: `pytest tests/test_fixer.py -v`
Expected: PASS (7 tests)

- [ ] **Step 6: Commit**

```bash
git add fixer.py tests/test_fixer.py
git commit -m "feat: add fix prompt building and diff application"
```

---

### Task 8: validator.py — re-scan, test run, retry/revert

**Files:**
- Create: `validator.py`
- Test: `tests/test_validator.py`

**Interfaces:**
- Consumes: `models.Finding`, `models.FixResult`, `models.ValidationResult` (Task 1).
- Consumes: `scanner.scan` (Task 3).
- Consumes: `fixer.fix_finding` (Task 7), used for retries.
- Produces: `validator.finding_still_present(original: Finding, rescanned: list[Finding]) -> bool`.
- Produces: `validator.run_test_suite(target_repo: str) -> tuple[bool, str]` — `(passed, output)`; `(True, "no tests found")` if no test suite detected.
- Produces: `validator.validate_and_retry(fix_result: FixResult, ollama, repo, target_repo: str, semgrep_rulesets: list[str], max_retries: int) -> ValidationResult`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_validator.py
from unittest.mock import MagicMock, patch

from models import Finding, FixResult
from validator import finding_still_present, run_test_suite, validate_and_retry


def make_finding():
    return Finding(
        file="sample_vuln_app/app.py",
        line=41,
        rule_id="python.flask.security.injection.sql-injection",
        cwe="CWE-89",
        message="Detected string-interpolated SQL query.",
        snippet="query = f\"...\"",
    )


def test_finding_still_present_true_when_same_rule_and_file_reappears():
    original = make_finding()
    rescanned = [make_finding()]
    assert finding_still_present(original, rescanned) is True


def test_finding_still_present_false_when_gone():
    original = make_finding()
    assert finding_still_present(original, []) is False


def test_run_test_suite_no_tests_dir(tmp_path):
    passed, output = run_test_suite(str(tmp_path))
    assert passed is True
    assert "no tests found" in output.lower()


def test_run_test_suite_runs_pytest_when_tests_dir_exists(tmp_path):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_dummy.py").write_text("def test_ok():\n    assert True\n")

    passed, output = run_test_suite(str(tmp_path))
    assert passed is True


def test_validate_and_retry_marks_validated_when_rescan_clean():
    finding = make_finding()
    fix_result = FixResult(finding=finding, diff="some diff", applied=True, branch="autofix/x")
    ollama = MagicMock()
    repo = MagicMock()

    with patch("validator.scan", return_value=[]), \
         patch("validator.run_test_suite", return_value=(True, "no tests found")):
        result = validate_and_retry(
            fix_result, ollama, repo, target_repo=".",
            semgrep_rulesets=["p/security-audit"], max_retries=2,
        )

    assert result.validated is True
    assert result.clean is True
    repo.git.checkout.assert_not_called()  # no revert needed


def test_validate_and_retry_retries_then_reverts_when_still_failing():
    finding = make_finding()
    fix_result = FixResult(finding=finding, diff="some diff", applied=True, branch="autofix/x")
    ollama = MagicMock()
    ollama.generate.return_value = "```diff\nstill broken\n```"
    repo = MagicMock()

    with patch("validator.scan", return_value=[finding]), \
         patch("validator.run_test_suite", return_value=(True, "no tests found")), \
         patch("validator.fix_finding") as mock_fix_finding:
        mock_fix_finding.return_value = fix_result

        result = validate_and_retry(
            fix_result, ollama, repo, target_repo=".",
            semgrep_rulesets=["p/security-audit"], max_retries=2,
        )

    assert result.validated is False
    assert mock_fix_finding.call_count == 2  # max_retries
    repo.git.checkout.assert_called_with("main")  # reverted off the branch
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_validator.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'validator'`

- [ ] **Step 3: Write `validator.py`**

```python
import os
import subprocess

from fixer import fix_finding
from models import Finding, FixResult, ValidationResult
from scanner import scan


def finding_still_present(original: Finding, rescanned: list[Finding]) -> bool:
    return any(
        f.rule_id == original.rule_id and f.file == original.file
        for f in rescanned
    )


def run_test_suite(target_repo: str) -> tuple[bool, str]:
    tests_dir = os.path.join(target_repo, "tests")
    if not os.path.isdir(tests_dir):
        return True, "no tests found"

    result = subprocess.run(
        ["pytest", tests_dir, "-v"],
        capture_output=True,
        text=True,
        cwd=target_repo,
    )
    return result.returncode == 0, result.stdout + result.stderr


def validate_and_retry(
    fix_result: FixResult,
    ollama,
    repo,
    target_repo: str,
    semgrep_rulesets: list[str],
    max_retries: int,
) -> ValidationResult:
    finding = fix_result.finding
    current_fix = fix_result
    last_output = ""

    for attempt in range(max_retries):
        rescanned = scan(target_repo, semgrep_rulesets)
        still_present = finding_still_present(finding, rescanned)
        tests_passed, test_output = run_test_suite(target_repo)
        last_output = test_output

        if not still_present and tests_passed:
            return ValidationResult(
                finding=finding,
                clean=True,
                test_output=test_output,
                validated=True,
            )

        feedback = (
            f"Rescan still found the issue: {still_present}. "
            f"Tests passed: {tests_passed}. Output: {test_output[:2000]}"
        )
        current_fix = fix_finding(finding, ollama, repo, retry_feedback=feedback)

    repo.git.checkout("main")
    return ValidationResult(
        finding=finding,
        clean=False,
        test_output=last_output,
        validated=False,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_validator.py -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add validator.py tests/test_validator.py
git commit -m "feat: add validation, retry, and revert logic"
```

---

### Task 9: pr.py — commit, branch, PR body, PyGithub

**Files:**
- Create: `pr.py`
- Test: `tests/test_pr.py`

**Interfaces:**
- Consumes: `models.TriageResult`, `models.ValidationResult` (Task 1).
- Produces: `pr.build_pr_body(entries: list[tuple[TriageResult, ValidationResult]]) -> str`.
- Produces: `pr.commit_validated_findings(repo, entries, strategy: str) -> list[str]` — returns branch names committed to.
- Produces: `pr.open_pr(github_client, repo_full_name: str, branch: str, title: str, body: str, dry_run: bool) -> str | None` — returns PR URL, or `None` on dry run.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_pr.py
from unittest.mock import MagicMock

from models import Finding, TriageResult, ValidationResult
from pr import build_pr_body, commit_validated_findings, open_pr


def make_entry(validated=True):
    finding = Finding(
        file="sample_vuln_app/app.py",
        line=41,
        rule_id="python.flask.security.injection.sql-injection",
        cwe="CWE-89",
        message="Detected string-interpolated SQL query.",
        snippet="query = f\"...\"",
    )
    triage = TriageResult(
        finding=finding,
        llm_reasoning="Exploitable, no upstream sanitization.",
        laya_score=0.92,
        route="fix",
    )
    validation = ValidationResult(
        finding=finding,
        clean=True,
        test_output="no tests found",
        validated=validated,
    )
    return triage, validation


def test_build_pr_body_includes_required_fields_per_finding():
    entries = [make_entry()]
    body = build_pr_body(entries)

    triage, validation = entries[0]
    assert triage.finding.cwe in body
    assert triage.finding.snippet in body
    assert triage.llm_reasoning in body
    assert "0.92" in body
    assert "validated" in body.lower()
    assert "re-scan clean" in body.lower() or "no tests found" in body.lower()


def test_build_pr_body_skips_non_validated_entries():
    entries = [make_entry(validated=False)]
    body = build_pr_body(entries)
    assert body.strip() == "" or "no validated findings" in body.lower()


def test_commit_validated_findings_single_strategy_uses_one_branch():
    repo = MagicMock()
    entries = [make_entry(), make_entry()]

    branches = commit_validated_findings(repo, entries, strategy="single")

    assert len(set(branches)) == 1
    repo.git.checkout.assert_called()
    repo.git.add.assert_called()
    repo.git.commit.assert_called()


def test_commit_validated_findings_per_finding_strategy_uses_multiple_branches():
    repo = MagicMock()
    entries = [make_entry(), make_entry()]

    branches = commit_validated_findings(repo, entries, strategy="per-finding")

    assert len(branches) == 2


def test_open_pr_dry_run_returns_none_and_does_not_call_github():
    github_client = MagicMock()
    url = open_pr(github_client, "r0hitpilla/sast-poc-vuln-app", "autofix/x", "title", "body", dry_run=True)

    assert url is None
    github_client.get_repo.assert_not_called()


def test_open_pr_creates_pull_request_when_not_dry_run():
    github_client = MagicMock()
    mock_repo = MagicMock()
    mock_pr = MagicMock()
    mock_pr.html_url = "https://github.com/r0hitpilla/sast-poc-vuln-app/pull/1"
    mock_repo.create_pull.return_value = mock_pr
    github_client.get_repo.return_value = mock_repo

    url = open_pr(github_client, "r0hitpilla/sast-poc-vuln-app", "autofix/x", "title", "body", dry_run=False)

    assert url == "https://github.com/r0hitpilla/sast-poc-vuln-app/pull/1"
    mock_repo.create_pull.assert_called_once_with(
        title="title", body="body", head="autofix/x", base="main"
    )
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_pr.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'pr'`

- [ ] **Step 3: Write `pr.py`**

```python
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
        for triage, _ in validated_entries:
            branch = f"autofix/{triage.finding.rule_id.replace('.', '-')}-L{triage.finding.line}"
            repo.git.checkout("-b", branch)
            repo.git.add(triage.finding.file)
            repo.git.commit("-m", f"fix: {triage.finding.cwe} at {triage.finding.file}:{triage.finding.line}")
            branches.append(branch)

    return branches


def open_pr(github_client, repo_full_name: str, branch: str, title: str, body: str, dry_run: bool):
    if dry_run:
        return None

    repo = github_client.get_repo(repo_full_name)
    pull = repo.create_pull(title=title, body=body, head=branch, base="main")
    return pull.html_url
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_pr.py -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add pr.py tests/test_pr.py
git commit -m "feat: add pr body building, commit strategy, and pygithub integration"
```

---

### Task 10: cli.py — fix, pr, run subcommands + README

**Files:**
- Modify: `cli.py`
- Create: `README.md`
- Test: `tests/test_cli_full_pipeline.py`

**Interfaces:**
- Consumes: everything from Tasks 1–9.
- Produces: `python cli.py fix --target-repo <path>`, `python cli.py pr --target-repo <path> [--dry-run]`, `python cli.py run --target-repo <path> [--dry-run]`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cli_full_pipeline.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cli_full_pipeline.py -v`
Expected: FAIL — `pr`/`run` subcommands don't exist yet, `argparse` raises `SystemExit` for the unrecognized `--dry-run` flag.

- [ ] **Step 3: Extend `cli.py` with `fix`, `pr`, and `run`**

Add these imports to the top of `cli.py` (alongside the existing ones):

```python
import os

import git
from github import Github

from fixer import fix_finding
from pr import build_pr_body, commit_validated_findings, open_pr
from validator import validate_and_retry
```

Add these functions to `cli.py`, after `cmd_triage`:

```python
def run_pipeline(target_repo: str, config_path: str, dry_run: bool):
    cfg = load_config(config_path)
    findings = scan(target_repo, cfg.semgrep_rulesets)
    ollama = OllamaClient(host=cfg.ollama_host, model=cfg.ollama_model)
    laya = LayaClient(model=cfg.laya_model)
    repo = git.Repo(target_repo)

    entries = []
    for finding in findings:
        triage_result = triage_finding(
            finding, ollama, laya, cfg.threshold_fix, cfg.threshold_review
        )
        if triage_result.route != "fix":
            continue

        fix_result = fix_finding(finding, ollama, repo)
        if not fix_result.applied:
            continue

        validation_result = validate_and_retry(
            fix_result, ollama, repo, target_repo,
            cfg.semgrep_rulesets, cfg.max_fix_retries,
        )
        entries.append((triage_result, validation_result))

    validated = [(t, v) for t, v in entries if v.validated]
    if not validated:
        print("No findings validated for a fix.")
        return

    branches = commit_validated_findings(repo, entries, cfg.pr_strategy)
    body = build_pr_body(entries)

    if dry_run:
        print("[dry-run] Would push branch(es):", set(branches))
        print("[dry-run] PR body:\n", body)
        return

    repo.git.push("--set-upstream", "origin", branches[0])
    github_client = Github(os.environ["GITHUB_TOKEN"])
    repo_full_name = os.environ.get("GITHUB_REPO", "r0hitpilla/sast-poc-vuln-app")
    url = open_pr(
        github_client, repo_full_name, branches[0],
        title="Automated security fixes (sast-autofix-poc)",
        body=body, dry_run=False,
    )
    print(f"Opened PR: {url}")


def cmd_fix(args):
    cfg = load_config(args.config)
    findings = scan(args.target_repo, cfg.semgrep_rulesets)
    ollama = OllamaClient(host=cfg.ollama_host, model=cfg.ollama_model)
    laya = LayaClient(model=cfg.laya_model)
    repo = git.Repo(args.target_repo)

    results = []
    for finding in findings:
        triage_result = triage_finding(
            finding, ollama, laya, cfg.threshold_fix, cfg.threshold_review
        )
        if triage_result.route != "fix":
            continue
        results.append(fix_finding(finding, ollama, repo))

    print(json.dumps([dataclasses.asdict(r) for r in results], indent=2, default=str))


def cmd_pr(args):
    run_pipeline(args.target_repo, args.config, args.dry_run)


def cmd_run(args):
    run_pipeline(args.target_repo, args.config, args.dry_run)
```

Add these subparsers inside `build_parser()`, before `return parser`:

```python
    fix_parser = sub.add_parser("fix", help="Scan, triage, and fix (no PR)")
    fix_parser.add_argument("--target-repo", default="sample_vuln_app")
    fix_parser.set_defaults(func=cmd_fix)

    pr_parser = sub.add_parser("pr", help="Full pipeline through PR creation")
    pr_parser.add_argument("--target-repo", default="sample_vuln_app")
    pr_parser.add_argument("--dry-run", action="store_true", default=False)
    pr_parser.set_defaults(func=cmd_pr)

    run_parser = sub.add_parser("run", help="Full pipeline: scan -> triage -> fix -> validate -> pr")
    run_parser.add_argument("--target-repo", default="sample_vuln_app")
    run_parser.add_argument("--dry-run", action="store_true", default=False)
    run_parser.set_defaults(func=cmd_run)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_cli_full_pipeline.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Run the full test suite**

Run: `pytest -v`
Expected: PASS — all tests from Tasks 1–10.

- [ ] **Step 6: Write `README.md`**

```markdown
# sast-autofix-poc

Local-LLM-powered pipeline: Semgrep scan -> Ollama + Laya triage -> Ollama
fix -> re-scan/test validate -> GitHub PR. No cloud LLM calls.

## Setup (on the DGX Spark, where Ollama + Semgrep are already installed)

    python -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt

Pull the default model if not already present:

    ollama pull hf.co/mradermacher/Qwen3-Coder-30B-A3B-Instruct-Heretic-i1-GGUF:Q4_K_M

Set your GitHub token (repo scope) before running `pr` or `run` for real:

    export GITHUB_TOKEN=ghp_...
    export GITHUB_REPO=r0hitpilla/sast-poc-vuln-app

## Usage

    python cli.py scan --target-repo sample_vuln_app
    python cli.py triage --target-repo sample_vuln_app
    python cli.py fix --target-repo sample_vuln_app
    python cli.py pr --target-repo sample_vuln_app --dry-run
    python cli.py run --target-repo sample_vuln_app --dry-run

Drop `--dry-run` once you're ready to actually push and open the PR.

## Config

All model names, thresholds, rulesets, and PR strategy live in
`config.yaml`. `OLLAMA_HOST` env var overrides `ollama.host` if set.

## sample_vuln_app

A deliberately vulnerable Flask app (SQL injection, path traversal, and a
cache-keyed race-condition privilege leak) used as the demo target. See
`sample_vuln_app/README.md`.

## Tests

    pytest -v
```

- [ ] **Step 7: Commit**

```bash
git add cli.py README.md tests/test_cli_full_pipeline.py
git commit -m "feat: wire fix/pr/run cli subcommands and add README"
```
