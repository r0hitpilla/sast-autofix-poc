"""Host and service health for the self-hosted box (DGX Spark)."""

import os
import shutil
import subprocess

import psutil

from .cache import ttl_cache

TOOL_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _gpu() -> list[dict]:
    if not shutil.which("nvidia-smi"):
        return []
    try:
        out = subprocess.run(
            ["nvidia-smi", "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu",
             "--format=csv,noheader,nounits"], capture_output=True, text=True, timeout=5, check=True,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return []

    def num(v):
        try:
            return float(v)
        except ValueError:
            return None  # "[N/A]" on unified-memory GPUs like the GB10
    gpus = []
    for line in out.strip().splitlines():
        name, util, used, total, temp = (p.strip() for p in line.split(","))
        gpus.append({"name": name, "utilization": num(util), "memory_used_mb": num(used),
                     "memory_total_mb": num(total), "temperature_c": num(temp)})
    return gpus


def _systemd_active(unit: str) -> bool:
    try:
        return subprocess.run(["systemctl", "is-active", "--quiet", unit], timeout=5).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _runner_unit(configured: str | None) -> str | None:
    if configured:
        return configured
    try:
        out = subprocess.run(["systemctl", "list-units", "--type=service", "--all", "--plain",
                              "--no-legend", "actions.runner.*"],
                             capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    units = [line.split()[0] for line in out.splitlines() if line.strip()]
    return units[0] if units else None


@ttl_cache(10)
def snapshot(runner_service: str | None) -> dict:
    disk = psutil.disk_usage(TOOL_DIR)
    mem = psutil.virtual_memory()
    unit = _runner_unit(runner_service)
    semgrep = os.path.join(TOOL_DIR, "venv", "bin", "semgrep")
    return {
        "cpu_percent": psutil.cpu_percent(interval=0.2),
        "memory_percent": mem.percent,
        "memory_total_gb": round(mem.total / 2**30, 1),
        "disk_percent": disk.percent,
        "load_avg": [round(x, 2) for x in os.getloadavg()],
        "gpus": _gpu(),
        "services": {
            "actions_runner": {"unit": unit, "ok": bool(unit) and _systemd_active(unit)},
            "semgrep": {"ok": os.path.exists(semgrep)},
            "pipeline_venv": {"ok": os.path.exists(os.path.join(TOOL_DIR, "venv", "bin", "python"))},
        },
    }
