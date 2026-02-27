"""
Unit tests for backend/utils/rate_limit.py — Phase 14 rate limiter.
"""

import time
import threading
import pytest
from unittest.mock import MagicMock
from fastapi import HTTPException

from backend.utils.rate_limit import RateLimiter


def _make_request(ip: str = "127.0.0.1") -> MagicMock:
    """Create a minimal fake FastAPI Request with a client IP."""
    req = MagicMock()
    req.headers = {}
    req.client = MagicMock()
    req.client.host = ip
    return req


class TestRateLimiterBasic:
    def test_allows_requests_within_limit(self):
        limiter = RateLimiter(requests=5, window=60)
        req = _make_request()
        for _ in range(5):
            limiter(req)  # should not raise

    def test_raises_429_when_exceeded(self):
        limiter = RateLimiter(requests=3, window=60)
        req = _make_request()
        for _ in range(3):
            limiter(req)
        with pytest.raises(HTTPException) as exc_info:
            limiter(req)
        assert exc_info.value.status_code == 429

    def test_429_detail_has_retry_after(self):
        limiter = RateLimiter(requests=1, window=60)
        req = _make_request()
        limiter(req)
        with pytest.raises(HTTPException) as exc_info:
            limiter(req)
        detail = exc_info.value.detail
        assert "retry_after" in detail
        assert detail["retry_after"] > 0

    def test_different_ips_tracked_independently(self):
        limiter = RateLimiter(requests=2, window=60)
        req_a = _make_request("1.1.1.1")
        req_b = _make_request("2.2.2.2")
        limiter(req_a)
        limiter(req_a)
        limiter(req_b)  # b has only 1 request — should not raise

    def test_window_expiry_resets_count(self):
        limiter = RateLimiter(requests=2, window=0.05)
        req = _make_request()
        limiter(req)
        limiter(req)
        time.sleep(0.1)
        limiter(req)  # window expired — should not raise

    def test_reset_clears_all(self):
        limiter = RateLimiter(requests=1, window=60)
        req = _make_request()
        limiter(req)
        limiter.reset()
        limiter(req)  # should not raise after reset

    def test_reset_single_ip(self):
        limiter = RateLimiter(requests=1, window=60)
        req_a = _make_request("1.1.1.1")
        req_b = _make_request("2.2.2.2")
        limiter(req_a)
        limiter(req_b)
        limiter.reset("1.1.1.1")
        limiter(req_a)  # should not raise
        with pytest.raises(HTTPException):
            limiter(req_b)  # b still at limit


class TestRateLimiterXForwardedFor:
    def test_honours_x_forwarded_for(self):
        limiter = RateLimiter(requests=1, window=60)
        req = MagicMock()
        req.headers = {"X-Forwarded-For": "9.9.9.9, 10.0.0.1"}
        req.client = MagicMock()
        req.client.host = "127.0.0.1"
        limiter(req)
        # Second call from same forwarded IP hits limit
        with pytest.raises(HTTPException):
            limiter(req)

    def test_uses_first_forwarded_ip(self):
        req = MagicMock()
        req.headers = {"X-Forwarded-For": "5.5.5.5, 6.6.6.6"}
        req.client = MagicMock()
        req.client.host = "127.0.0.1"
        ip = RateLimiter._get_ip(req)
        assert ip == "5.5.5.5"

    def test_falls_back_to_client_host(self):
        req = MagicMock()
        req.headers = {}
        req.client = MagicMock()
        req.client.host = "3.3.3.3"
        assert RateLimiter._get_ip(req) == "3.3.3.3"

    def test_returns_unknown_without_client(self):
        req = MagicMock()
        req.headers = {}
        req.client = None
        assert RateLimiter._get_ip(req) == "unknown"


class TestRateLimiterState:
    def test_state_reflects_current_usage(self):
        limiter = RateLimiter(requests=10, window=60)
        req = _make_request("4.4.4.4")
        limiter(req)
        limiter(req)
        s = limiter.state("4.4.4.4")
        assert s["requests"] == 2
        assert s["remaining"] == 8
        assert s["limit"] == 10

    def test_state_unknown_ip_returns_zero(self):
        limiter = RateLimiter(requests=10, window=60)
        s = limiter.state("99.99.99.99")
        assert s["requests"] == 0
        assert s["remaining"] == 10


class TestRateLimiterThreadSafety:
    def test_concurrent_requests_dont_crash(self):
        limiter = RateLimiter(requests=1000, window=60)
        req = _make_request()
        errors = []

        def hit():
            try:
                limiter(req)
            except HTTPException:
                pass  # 429 is ok
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=hit) for _ in range(50)]
        for t in threads: t.start()
        for t in threads: t.join()
        assert errors == []


class TestPrebuiltLimiters:
    def test_scan_rate_limiter_exists(self):
        from backend.utils.rate_limit import scan_rate_limiter
        assert scan_rate_limiter._requests == 20

    def test_target_rate_limiter_exists(self):
        from backend.utils.rate_limit import target_rate_limiter
        assert target_rate_limiter._requests == 30

    def test_read_rate_limiter_exists(self):
        from backend.utils.rate_limit import read_rate_limiter
        assert read_rate_limiter._requests == 120
