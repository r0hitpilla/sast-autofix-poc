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
    max_fix_retries: int
    # Max follow-up questions Laya may put to the LLM per finding.
    triage_max_rounds: int = 3
    # LLM security review of each fix before it is accepted.
    fix_review: bool = True
    # Models used for fix attempts, rotated across retries.
    fix_models: list = None
    # Scanners run on every pass: semgrep (SAST), gitleaks (secrets), osv (dependencies).
    engines: tuple = ("semgrep",)
    # The dashboard's base URL: earlier runs' findings are read from it. None: no history.
    dashboard_url: str | None = None
    # The dashboard's machine token; the history is refused without it.
    dashboard_token: str | None = None
    # Tracing of every AI call to a self-hosted Langfuse (see observability.py).
    # The API keys are not configuration: they come from the environment or a
    # private file, never from this repository.
    # Exploit test per fix (see proof.py): off | advisory | required.
    proof_mode: str = "advisory"
    proof_attempts: int = 3
    proof_timeout: int = 60
    langfuse_enabled: bool = False
    langfuse_host: str = "http://127.0.0.1:3000"
    langfuse_allow_cloud: bool = False      # prompts contain source code: keep this off
    langfuse_capture_content: bool = True   # False: send token/timing metadata only


def resolve_ruleset(ruleset: str, config_dir: str) -> str:
    """Registry packs ("p/...") pass through; local rule files are made
    absolute, because Semgrep runs with cwd set to the target repo."""
    local = os.path.join(config_dir, ruleset)
    return local if os.path.exists(local) else ruleset


def load_config(path: str = "config.yaml") -> Config:
    with open(path) as f:
        raw = yaml.safe_load(f)

    langfuse = (raw.get("observability") or {}).get("langfuse") or {}
    proof = raw.get("proof_of_fix") or {}
    if proof.get("mode", "advisory") not in ("off", "advisory", "required"):
        raise ValueError("proof_of_fix.mode must be off, advisory or required")

    return Config(
        ollama_host=os.environ.get("OLLAMA_HOST", raw["ollama"]["host"]),
        ollama_model=raw["ollama"]["model"],
        laya_model=raw["laya"]["model"],
        threshold_fix=raw["thresholds"]["fix"],
        threshold_review=raw["thresholds"]["review"],
        semgrep_rulesets=[
            resolve_ruleset(r, os.path.dirname(os.path.abspath(path)))
            for r in raw["semgrep"]["rulesets"]
        ],
        max_fix_retries=raw["max_fix_retries"],
        triage_max_rounds=raw.get("laya", {}).get("max_rounds", 3),
        fix_review=raw.get("fix_review", True),
        fix_models=raw["ollama"].get("fix_models") or [raw["ollama"]["model"]],
        engines=tuple(raw.get("engines", ["semgrep"])),
        dashboard_url=os.environ.get("SAST_DASHBOARD_URL", raw.get("dashboard_url")) or None,
        dashboard_token=os.environ.get("SAST_DASHBOARD_TOKEN") or None,
        proof_mode=proof.get("mode", "advisory"),
        proof_attempts=int(proof.get("attempts", 3)),
        proof_timeout=int(proof.get("timeout_seconds", 60)),
        langfuse_enabled=bool(langfuse.get("enabled", False)),
        langfuse_host=langfuse.get("host", "http://127.0.0.1:3000"),
        langfuse_allow_cloud=bool(langfuse.get("allow_cloud", False)),
        langfuse_capture_content=bool(langfuse.get("capture_content", True)),
    )
