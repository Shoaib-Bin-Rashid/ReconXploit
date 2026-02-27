"""
Unit tests for backend/utils/cache.py — Phase 14 TTL cache.
"""

import time
import threading
import pytest
from unittest.mock import MagicMock

from backend.utils.cache import ttl_cache, _TTLCache, invalidate_prefix, cache_clear_all


# ──────────────────────────────────────────────────────────────────────────────
# _TTLCache internals
# ──────────────────────────────────────────────────────────────────────────────

class TestTTLCacheInternal:
    def test_set_and_get(self):
        c = _TTLCache()
        c.set("k", "v", ttl=10)
        hit, val = c.get("k")
        assert hit is True
        assert val == "v"

    def test_miss_returns_false(self):
        c = _TTLCache()
        hit, val = c.get("missing")
        assert hit is False
        assert val is None

    def test_expired_entry_not_returned(self):
        c = _TTLCache()
        c.set("k", "v", ttl=0.001)
        time.sleep(0.01)
        hit, _ = c.get("k")
        assert hit is False

    def test_delete_removes_entry(self):
        c = _TTLCache()
        c.set("k", "v", ttl=60)
        c.delete("k")
        hit, _ = c.get("k")
        assert hit is False

    def test_clear_removes_all(self):
        c = _TTLCache()
        c.set("a", 1, ttl=60)
        c.set("b", 2, ttl=60)
        c.clear()
        assert len(c) == 0

    def test_eviction_on_maxsize(self):
        c = _TTLCache(maxsize=2)
        c.set("a", 1, ttl=0.001)  # will expire quickly
        c.set("b", 2, ttl=0.001)
        time.sleep(0.01)
        # Next set triggers eviction of expired entries
        c.set("c", 3, ttl=60)
        assert len(c) == 1

    def test_thread_safe(self):
        c = _TTLCache()
        errors = []

        def writer(i):
            try:
                for _ in range(50):
                    c.set(f"k{i}", i, ttl=5)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(10)]
        for t in threads: t.start()
        for t in threads: t.join()
        assert errors == []


# ──────────────────────────────────────────────────────────────────────────────
# ttl_cache decorator
# ──────────────────────────────────────────────────────────────────────────────

class TestTtlCacheDecorator:
    def test_caches_result(self):
        call_count = 0

        @ttl_cache(ttl=60)
        def expensive():
            nonlocal call_count
            call_count += 1
            return 42

        expensive.cache_clear()
        assert expensive() == 42
        assert expensive() == 42
        assert call_count == 1

    def test_different_args_different_entries(self):
        call_count = 0

        @ttl_cache(ttl=60)
        def fn(x):
            nonlocal call_count
            call_count += 1
            return x * 2

        fn.cache_clear()
        fn(1)
        fn(2)
        fn(1)
        assert call_count == 2

    def test_cache_expires(self):
        call_count = 0

        @ttl_cache(ttl=0.01)
        def fn():
            nonlocal call_count
            call_count += 1
            return "x"

        fn.cache_clear()
        fn()
        time.sleep(0.05)
        fn()
        assert call_count == 2

    def test_cache_clear_resets(self):
        call_count = 0

        @ttl_cache(ttl=60)
        def fn():
            nonlocal call_count
            call_count += 1
            return "v"

        fn.cache_clear()
        fn()
        fn.cache_clear()
        fn()
        assert call_count == 2

    def test_key_prefix_used(self):
        @ttl_cache(ttl=60, key_prefix="myns.fn")
        def fn():
            return 1

        fn.cache_clear()
        fn()
        # Should be stored under myns.fn:... key
        from backend.utils.cache import _cache
        matching = [k for k in _cache._store if k.startswith("myns.fn:")]
        assert len(matching) >= 1

    def test_preserves_function_name(self):
        @ttl_cache(ttl=60)
        def my_func():
            return 1
        assert my_func.__name__ == "my_func"


# ──────────────────────────────────────────────────────────────────────────────
# invalidate_prefix / cache_clear_all
# ──────────────────────────────────────────────────────────────────────────────

class TestInvalidation:
    def test_invalidate_prefix_removes_matching(self):
        from backend.utils.cache import _cache
        _cache.set("ns.a:1", 1, 60)
        _cache.set("ns.a:2", 2, 60)
        _cache.set("other:1", 3, 60)
        invalidate_prefix("ns.a")
        assert _cache.get("ns.a:1")[0] is False
        assert _cache.get("ns.a:2")[0] is False
        assert _cache.get("other:1")[0] is True
        _cache.delete("other:1")

    def test_cache_clear_all_empties_cache(self):
        from backend.utils.cache import _cache
        _cache.set("x", 1, 60)
        cache_clear_all()
        assert len(_cache) == 0
