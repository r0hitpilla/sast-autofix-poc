"""Model inventory and liveness from the local Ollama server."""

import time

import httpx

from ..settings import get_settings
from .cache import ttl_cache


@ttl_cache(15)
def status() -> dict:
    host = get_settings().ollama_host.rstrip("/")
    try:
        t0 = time.monotonic()
        version = httpx.get(f"{host}/api/version", timeout=3).json().get("version")
        latency_ms = round((time.monotonic() - t0) * 1000, 1)
        tags = httpx.get(f"{host}/api/tags", timeout=5).json().get("models", [])
        loaded = httpx.get(f"{host}/api/ps", timeout=5).json().get("models", [])
    except (httpx.HTTPError, ValueError) as exc:
        return {"online": False, "error": str(exc)[:200], "models": []}
    loaded_names = {m.get("name") for m in loaded}
    return {
        "online": True, "version": version, "api_latency_ms": latency_ms,
        "models": [{
            "name": m.get("name"),
            "parameter_size": (m.get("details") or {}).get("parameter_size"),
            "quantization": (m.get("details") or {}).get("quantization_level"),
            "family": (m.get("details") or {}).get("family"),
            "size_bytes": m.get("size"),
            "loaded": m.get("name") in loaded_names,
        } for m in tags],
    }
