# Prerequisites

What must exist before the SAST Autofix PoC runs. Values in the "Today" column are what the reference machine (a DGX Spark) runs now.

## 1. Hardware and OS

| Item | Today | Minimum to reproduce |
|---|---|---|
| Machine | NVIDIA GB10 (DGX Spark), arm64, Ubuntu 24.04 | Linux host with a GPU or unified memory that holds the models |
| Memory | 121 GB (shared CPU/GPU) | ~32 GB free for the 35B model alone; more if triage and fix models are loaded together |
| Disk | 3.7 TB, 9% used | ~100 GB: model weights (13-25 GB each), Langfuse data, Postgres |
| CPU | 20 cores | 8+ |

## 2. Models (all local; no model API calls leave the machine)

| Role | Model | Served by |
|---|---|---|
| Triage and fix review | `qwen3.5:35b-a3b` (23 GB) | Ollama on `localhost:11434` |
| Fix writing (attempts alternate) | `qwen3.5:35b-a3b`, `qwen3-coder-aida:latest` (18 GB) | Ollama |
| Proof-of-fix exploit tests | the same models | Ollama |
| Laya (finding score, fix trust score) | `convaiinnovations/laya` | Hugging Face weights loaded in-process by the `laya` Python package, cached under `~/.cache/huggingface` (not an Ollama model) |

Ollama 0.30.x. Models are chosen in `config.yaml` (`ollama.model`, `ollama.fix_models`, `laya.model`).

## 3. Scanners (on the host)

| Tool | Version | Notes |
|---|---|---|
| Semgrep | 1.178 | Installed in the pipeline venv, not on `PATH`. Packs `p/security-audit` and `p/owasp-top-ten` are fetched from semgrep.dev; custom rules are in `rules/`. |
| gitleaks | 8.30 | Secrets |
| osv-scanner | 2.6 | Dependency CVEs; needs the OSV database online. Retries and a manifest-hash cache are built in. |

## 4. Runtimes and datastores

- **Python 3.12.** Two venvs that must stay separate: `venv/` (pipeline, Semgrep pins OpenTelemetry 1.37) and `dashboard/.venv` (FastAPI needs 1.44+). Never install dashboard packages into `venv/`.
- **Node 22**, only to build the React UI (`ui/web`).
- **PostgreSQL 16**, database `sast_autofix`, peer authentication as the service user. Alembic applies the schema when the dashboard starts.
- **Docker with Compose** for self-hosted Langfuse 4.x (Postgres, ClickHouse, Redis, MinIO, web, worker).

## 5. Services

| Service | Address | How it runs |
|---|---|---|
| Dashboard (FastAPI + React) | 127.0.0.1:8710 | systemd user unit `sast-autofix-dashboard` (`deploy/`) |
| Langfuse | 127.0.0.1:3000 | Docker Compose in `deploy/langfuse/` (`setup.sh`) |
| Ollama | 127.0.0.1:11434 | system service |
| GitHub Actions runner | none | systemd service, label `sast-autofix` |

Everything listens on loopback. Use an SSH tunnel to reach the UIs from another machine.

## 6. GitHub

- A repository per scanned app, with the workflow copied from `ci/sast-autofix.yml`.
- A **self-hosted runner** on the same machine. The workflow runs the tool from the local checkout, so tool changes apply without pushing.
- **Branch protection on `main`:** PR required, required status check `autofix`, no bypass.
- **Tokens** (created by the account owner): `GITHUB_TOKEN` (PRs, commit statuses); `SAST_HISTORY_TOKEN` and `SAST_DASHBOARD_TOKEN` if CI runs should read history and policy from the dashboard.

## 7. Secrets and files

| File | Holds | Mode |
|---|---|---|
| `~/.config/sast-autofix/langfuse.env` | Langfuse host and API keys (read by the pipeline and the dashboard) | 600, refused otherwise |
| `~/.config/sast-autofix/dashboard.env` | dashboard secrets and tokens | 600 |
| `deploy/langfuse/.env` | Langfuse container secrets and the UI admin login | 600, git-ignored |

## 8. Network

Outbound internet is needed only for: Semgrep rule packs, the OSV database, GitHub, and first-time pulls of Docker images and model weights. After that, scans of already-cached content work with limited connectivity, except OSV and GitHub. Langfuse Cloud is refused unless `allow_cloud: true`, because prompts contain source code.

## 9. First-time setup order

1. Install Ollama; pull the models in section 2; make sure the `laya` weights download once.
2. Install Semgrep (pipeline venv), gitleaks, osv-scanner.
3. `python3 -m venv venv && venv/bin/pip install -r requirements.txt`
4. PostgreSQL: create the `sast_autofix` database; `python3 -m venv dashboard/.venv && dashboard/.venv/bin/pip install -r dashboard/requirements.txt`
5. `cd ui/web && npm ci && npm run build`
6. Install and start the dashboard unit (instructions in `deploy/`).
7. `deploy/langfuse/setup.sh` (creates the keys file and starts Langfuse).
8. Register the GitHub runner; add the workflow and branch protection; create the tokens.

## 10. Known limits

- Proof-of-fix tests are tuned on the demo app only; test on other apps before setting `proof_of_fix.mode: required`.
- Exploit tests run on the CI host with a scrubbed environment, a timeout and resource limits, but not in a container or VM.
- The AI review step is token-heavy (about 2,300 output tokens per call).
- Account limits on the reference GitHub account (billing, full artifact quota) make the report-upload step non-fatal.
