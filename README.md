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
