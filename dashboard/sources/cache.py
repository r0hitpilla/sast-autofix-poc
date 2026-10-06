import threading
import time
from functools import wraps


def ttl_cache(seconds: float):
    """Memoize a function's result per-arguments for `seconds`. Live sources
    (GitHub, Ollama, nvidia-smi) are slow or rate-limited; dashboards poll."""
    def deco(fn):
        store, lock = {}, threading.Lock()

        @wraps(fn)
        def wrapper(*args):
            now = time.monotonic()
            with lock:
                hit = store.get(args)
                if hit and now - hit[0] < seconds:
                    return hit[1]
            value = fn(*args)
            with lock:
                store[args] = (now, value)
            return value
        wrapper.cache_clear = store.clear
        return wrapper
    return deco
