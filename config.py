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
