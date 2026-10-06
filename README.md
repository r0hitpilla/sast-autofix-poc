# sast-autofix-poc

Local-LLM-powered pipeline: Semgrep scan -> Laya-driven triage (Laya asks
the Ollama LLM for evidence) -> Ollama fix -> re-scan/test, re-fix until clean
-> GitHub PR annotated line by line. No cloud LLM calls.

## How it works

1. **Triage, with Laya in the middle.** The LLM writes an initial analysis.
   Each round, Laya scores the evidence so far and picks which question it
   wants the LLM to answer next: input source, sanitization, reachability,
   sink safety, or exploit. It stops once its score leaves the review band
   or after `laya.max_rounds` questions. Laya's final score routes the
   finding to fix (above `thresholds.fix`), review, or reject.
2. **Remediate + rescan loop.** The LLM gets the numbered source around the
   finding and returns a diff. The diff is applied, then Semgrep rescans and
   tests run. If the finding is still there, the rescan result goes back to
   the LLM for another attempt, up to `max_fix_retries` times. A fix that
   never validates is rolled back to the file's pre-fix snapshot, so earlier
   validated fixes in the same file survive. A final full rescan lists
   anything left.
3. **PR with exact lines.** The PR body has a "Changed lines" table. It maps
   each finding to the exact lines changed (taken from the branch's real diff
   against `main`, with links to those lines) and shows a was/now diff per
   finding. An inline review comment is pinned to every changed range. A
   change not tied to any finding is flagged separately.

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

## Trust model / prompt-injection surface

This tool feeds source code from the scanned repository straight into a local
LLM and auto-applies the diff that comes back, with no scope validation on
which files that diff touches. A comment or string in the scanned repo can
therefore attempt to steer the model into emitting a patch that changes
unrelated code. Only point it at repositories whose contents you already
trust, treat every LLM-generated diff as unreviewed until a human has read
the resulting pull request, and never merge one of its PRs without human
review.

## Config

All model names, thresholds, rulesets, and PR strategy live in
`config.yaml`. `OLLAMA_HOST` env var overrides `ollama.host` if set.

## sample_vuln_app

A deliberately vulnerable Flask app (SQL injection, path traversal, and a
cache-keyed race-condition privilege leak) used as the demo target. See
`sample_vuln_app/README.md`.

## Tests

    pytest -v
