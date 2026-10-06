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


def resolve_ruleset(ruleset: str, config_dir: str) -> str:
    """Registry packs ("p/...") pass through; local rule files are made
    absolute, because Semgrep runs with cwd set to the target repo."""
    local = os.path.join(config_dir, ruleset)
    return local if os.path.exists(local) else ruleset


def load_config(path: str = "config.yaml") -> Config:
    with open(path) as f:
        raw = yaml.safe_load(f)

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
    )
