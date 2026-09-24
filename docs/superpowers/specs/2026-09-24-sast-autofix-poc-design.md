# SAST Autofix POC — Design Spec

Date: 2026-09-24

## Purpose

Client demo of a local-LLM-powered pipeline: scan a codebase for vulnerabilities
with Semgrep, triage findings with a local Ollama model + Laya calibrated scoring,
auto-fix high-confidence true positives, validate the fix, and open a GitHub PR.
No cloud LLM calls — everything runs on the user's DGX Spark (Ollama + Semgrep
already installed there).

## Architecture

Five-stage pipeline, each stage a CLI subcommand runnable standalone:

1. **scan** (`scanner.py`) — run `semgrep --config p/security-audit --config
   p/owasp-top-ten --json` as a subprocess against `--target-repo`. Parse into
   `Finding` objects: file, line, rule_id, cwe, message, ~10-line code snippet.
2. **triage** (`triage.py`), per finding:
   - Call local Ollama model with finding + snippet, ask for plain-text reasoning
     on real-vs-false-positive and anything static analysis might miss.
   - Call `laya` (`noul`, model `convaiinnovations/laya`) with the finding + LLM
     reasoning as context, question "is this a true positive security
     vulnerability" → calibrated `P(true)` in [0, 1].
   - Route: `> 0.8` → fix; `0.4–0.8` → human review (skip auto-fix); `< 0.4` →
     likely false positive (skip). Any Ollama/Laya call failure routes to
     `review`, never silently to false-positive.
3. **fix** (`fixer.py`), findings routed to `fix` only — prompt Ollama for a
   minimal unified diff on just the vulnerable lines, apply to a working copy on
   a new branch (`git apply` via GitPython).
4. **validate** (`validator.py`) — re-run Semgrep on the patched file; if the
   original finding is gone, `validated=True`. Run the target repo's test suite
   if present. On failure, retry fix (feeding the failure back to the model) up
   to `max_fix_retries` (default 2), then revert that finding's changes and drop
   it from the PR.
5. **pr** (`pr.py`) — for all `validated=True` findings, commit to a single
   branch (default) or one branch per finding (`pr.strategy: per-finding`).
   Open a GitHub PR via PyGithub (`GITHUB_TOKEN` env var). PR body per finding:
   CWE, original vulnerable snippet, LLM triage reasoning, Laya score, and
   validation result ("re-scan clean" or test output). `--dry-run` runs
   everything except the push/PR call.

`cli.py` exposes `scan`, `triage`, `fix`, `pr`, and `run` (full pipeline)
subcommands, so scan+triage can be tested standalone before fix/pr exist.

## Repos

Two separate git repos, both under this project folder:

- **Pipeline tool** — this folder (`SAST-AUTOFIX-POC`), root of the
  `sast_autofix_poc` package. Local-only for now; not pushed unless the user
  asks.
- **Demo target** — `sample_vuln_app/`, its own git repo with its own remote
  (`https://github.com/r0hitpilla/sast-poc-vuln-app.git`), gitignored from the
  pipeline repo. The pipeline points at it via `--target-repo sample_vuln_app`
  (configurable, not hardcoded — the same pipeline could target any repo).

## sample_vuln_app

Small Flask app with three deliberate bugs:

1. SQL injection — raw string-interpolated query in a search/lookup route.
2. Path traversal — file-serving route joins user input into a path without
   containment checks.
3. Custom logic bug (non-famous, resists pure pattern-matching from training
   data) — a role/permission check whose backing state is cached per-process
   keyed incorrectly, so one request's elevated privilege can leak to a
   concurrent request under load. Semgrep should still catch the taint/logic
   shape; it's not a copy-paste textbook snippet.

## Config (`config.yaml`)

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

## Error handling

- Semgrep subprocess failure → hard stop, no partial pipeline run.
- Ollama/Laya call failure → route finding to `review`, log the error, never
  drop it as a false positive by default.
- Patch apply failure → same retry-then-revert path as a failed validation.

## Testing / rollout order

1. Scaffold both repos.
2. Build `sample_vuln_app` (3 vulns), init its own git repo, push to
   `sast-poc-vuln-app` on GitHub (needs `GITHUB_TOKEN` with repo scope — not
   yet set in this environment, push step blocked until provided).
3. `scanner.py` + `triage.py` — user tests `cli.py scan` / `cli.py triage`
   against `sample_vuln_app` on the DGX Spark.
4. `fixer.py` + `validator.py`.
5. `pr.py`.

## Open items resolved

- Repo setup: own local git repo + new GitHub repo for `sample_vuln_app`.
- Dependency management: venv + `requirements.txt`.
- PR default strategy: single PR for all validated fixes.
- Ollama/Semgrep: already installed on the user's DGX Spark; pipeline code runs
  there, `ollama.host` stays `localhost:11434`.
- Laya: verified real, `pip install laya`, `convaiinnovations/laya`, `noul`
  question type returns calibrated `P(true)`.
