"""
ReconXploit - Simple TTL Cache
Phase 14: In-memory cache for expensive aggregations.

Usage:
    from backend.utils.cache import ttl_cache

    @ttl_cache(ttl=60)
    def get_overview():
        ...

    # Invalidate explicitly:
    get_overview.cache_clear()
"""

import time
import threading
import functools
import hashlib
import json
from typing import Any, Callable, Optional


class _TTLCache:
    """Thread-safe dict with per-entry TTL eviction."""

    def __init__(self, maxsize: int = 512):
        self._store: dict[str, tuple[Any, float]] = {}
        self._lock  = threading.Lock()
        self._maxsize = maxsize

    def get(self, key: str) -> tuple[bool, Any]:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return False, None
            value, expires_at = entry
            if time.monotonic() > expires_at:
                del self._store[key]
                return False, None
            return True, value

    def set(self, key: str, value: Any, ttl: float):
        with self._lock:
            # Simple eviction: if over maxsize, drop all expired entries first
            if len(self._store) >= self._maxsize:
                now = time.monotonic()
                expired = [k for k, (_, exp) in self._store.items() if now > exp]
                for k in expired:
                    del self._store[k]
            self._store[key] = (value, time.monotonic() + ttl)

    def delete(self, key: str):
        with self._lock:
            self._store.pop(key, None)

    def clear(self):
        with self._lock:
            self._store.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)


# Module-level shared instance
_cache = _TTLCache(maxsize=512)


def ttl_cache(ttl: float = 30, key_prefix: str = ""):
    """
    Decorator that caches the return value of a function for `ttl` seconds.

    Args:
        ttl        : seconds to keep entry alive (default 30)
        key_prefix : optional namespace prefix

    The cache key is derived from the function's qualified name + JSON-encoded args.
    Adds a `.cache_clear()` method to the decorated function.
    """
    def decorator(fn: Callable) -> Callable:
        prefix = key_prefix or f"{fn.__module__}.{fn.__qualname__}"

        def _make_key(*args, **kwargs) -> str:
            raw = json.dumps({"a": args, "k": kwargs}, sort_keys=True, default=str)
            return f"{prefix}:{hashlib.md5(raw.encode()).hexdigest()}"

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            key = _make_key(*args, **kwargs)
            hit, val = _cache.get(key)
            if hit:
                return val
            val = fn(*args, **kwargs)
            _cache.set(key, val, ttl)
            return val

        def cache_clear():
            """Remove ALL entries whose key starts with this function's prefix."""
            with _cache._lock:
                to_del = [k for k in _cache._store if k.startswith(prefix)]
                for k in to_del:
                    del _cache._store[k]

        wrapper.cache_clear = cache_clear  # type: ignore[attr-defined]
        return wrapper

    return decorator


def invalidate_prefix(prefix: str):
    """Remove all cache entries whose key starts with `prefix`."""
    with _cache._lock:
        to_del = [k for k in _cache._store if k.startswith(prefix)]
        for k in to_del:
            del _cache._store[k]


def cache_clear_all():
    """Wipe the entire cache (e.g. after a scan completes)."""
    _cache.clear()
