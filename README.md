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

## Running automatically on GitHub

The intended flow, for a developer branch called `SV`:

    developer pushes SV
      -> workflow scans the whole repo as it is on SV
      -> Laya-driven triage, fix + rescan loop
      -> validated fixes pushed to SV-fix
      -> PR  SV-fix -> SV  with every changed line (table, links, inline
         comments) plus suggestions for findings it could not auto-fix
    developer merges SV-fix into SV, then SV into main as usual

Pushing to SV again rebuilds SV-fix from the latest SV and updates the same
PR. Nothing is ever pushed to `main` or to the developer's branch directly.

`ci/sast-autofix.yml` implements this. It runs on pushes to any branch except
`main` and `*-fix`, on a **self-hosted runner on the DGX Spark**, because
Ollama, Laya and Semgrep are local there. No source code goes to a cloud LLM.

One-time setup for a repo (e.g. `r0hitpilla/sast-poc-vuln-app`):

1. Copy `ci/sast-autofix.yml` to `.github/workflows/sast-autofix.yml` on
   `main`, so every branch developers create from `main` carries it.
2. **Settings → Actions → General → Workflow permissions:** turn on "Allow
   GitHub Actions to create and approve pull requests".
3. **Settings → Actions → Runners → New self-hosted runner** (Linux, ARM64).
   Run its commands on the DGX Spark with `--labels sast-autofix` added to
   `./config.sh`, then `sudo ./svc.sh install <user> && sudo ./svc.sh start`.
4. Optional: if this tool lives somewhere other than
   `/home/rcxdigital/SAST-AUTOFIX-POC/sast-autofix-poc`, set the repo
   variable `SAST_AUTOFIX_HOME`.

Each run writes a report (findings, Laya verdicts and the questions it asked,
fix attempts, what's still flagged, stage timings) to the run's **job
summary** page.

The same flow locally:

    python cli.py run --target-repo path/to/repo --base-branch SV --dry-run

The workflow deliberately does not run on `pull_request`. On a public repo
that would let pull requests from forks run code on your self-hosted runner.

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

All model names, thresholds, rulesets and retry limits live in
`config.yaml`. `OLLAMA_HOST` env var overrides `ollama.host` if set.

## sample_vuln_app

A deliberately vulnerable Flask app (SQL injection, path traversal, and a
cache-keyed race-condition privilege leak) used as the demo target. See
`sample_vuln_app/README.md`.

## Tests

    pytest -v
