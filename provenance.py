"""What produced a run's decisions: models, generation settings, thresholds,
rule packs and tool versions. Recorded in every report so any verdict or
patch can be traced back to exactly what made it."""

import functools
import os
import subprocess
from importlib import metadata

from ollama_client import GENERATION_OPTIONS

TOOL_DIR = os.path.dirname(os.path.abspath(__file__))


def _version(package: str) -> str | None:
    try:
        return metadata.version(package)
    except metadata.PackageNotFoundError:
        return None


@functools.cache
def tool_version() -> str:
    """The tool's git commit, with "+dirty" if it has uncommitted changes."""
    try:
        sha = subprocess.run(["git", "rev-parse", "--short=12", "HEAD"], cwd=TOOL_DIR,
                             capture_output=True, text=True, check=True).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"],
                               cwd=TOOL_DIR, capture_output=True, text=True).stdout.strip()
        return sha + ("+dirty" if dirty else "")
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def provenance(cfg) -> dict:
    return {
        "tool_version": tool_version(),
        "triage_model": cfg.ollama_model,
        "fix_models": list(cfg.fix_models),
        "laya_model": cfg.laya_model,
        "laya_version": _version("laya"),
        "semgrep_version": _version("semgrep"),
        "generation": dict(GENERATION_OPTIONS),
        "thresholds": {"fix": cfg.threshold_fix, "review": cfg.threshold_review},
        "triage_max_rounds": cfg.triage_max_rounds,
        "max_fix_retries": cfg.max_fix_retries,
        "fix_review": cfg.fix_review,
        # local rule dirs are absolute paths on the runner; keep just the name
        "rulesets": [r if r.startswith("p/") else os.path.basename(r.rstrip("/")) + "/"
                     for r in cfg.semgrep_rulesets],
    }
