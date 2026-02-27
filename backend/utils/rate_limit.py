"""
ReconXploit - Rate Limiter (sliding window, in-memory)
Phase 14: Protect scan-trigger and write endpoints from abuse.

Usage (FastAPI dependency):
    from backend.utils.rate_limit import RateLimiter

    scan_limiter = RateLimiter(requests=10, window=60)

    @router.post("")
    def trigger_scan(body: ..., _: None = Depends(scan_limiter)):
        ...
"""

import time
import threading
from collections import deque
from typing import Deque, Dict

from fastapi import HTTPException, Request


class RateLimiter:
    """
    Sliding-window rate limiter keyed by client IP.

    Args:
        requests : maximum number of requests allowed in `window` seconds
        window   : time window in seconds
    """

    def __init__(self, requests: int = 60, window: int = 60):
        self._requests = requests
        self._window   = window
        self._clients: Dict[str, Deque[float]] = {}
        self._lock = threading.Lock()

    def __call__(self, request: Request) -> None:
        """FastAPI dependency — raises 429 if rate exceeded."""
        ip = self._get_ip(request)
        now = time.monotonic()

        with self._lock:
            q = self._clients.setdefault(ip, deque())

            # Evict timestamps outside the window
            while q and now - q[0] > self._window:
                q.popleft()

            if len(q) >= self._requests:
                retry_after = int(self._window - (now - q[0])) + 1
                raise HTTPException(
                    status_code=429,
                    detail={
                        "error":       True,
                        "status":      429,
                        "message":     "Rate limit exceeded. Slow down.",
                        "retry_after": retry_after,
                    },
                )

            q.append(now)

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _get_ip(request: Request) -> str:
        """Return the real client IP, honouring X-Forwarded-For if present."""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        if request.client:
            return request.client.host
        return "unknown"

    def reset(self, ip: str = "") -> None:
        """Clear rate-limit state (all IPs, or just one IP)."""
        with self._lock:
            if ip:
                self._clients.pop(ip, None)
            else:
                self._clients.clear()

    def state(self, ip: str) -> Dict:
        """Return current window state for an IP (useful for testing)."""
        now = time.monotonic()
        with self._lock:
            q = self._clients.get(ip, deque())
            valid = [t for t in q if now - t <= self._window]
            return {
                "ip":        ip,
                "requests":  len(valid),
                "limit":     self._requests,
                "window":    self._window,
                "remaining": max(0, self._requests - len(valid)),
            }


# ── Pre-built limiters (imported by routers) ──────────────────────────────────

# Scan triggers: max 20/minute per IP (scans are expensive)
scan_rate_limiter = RateLimiter(requests=20, window=60)

# Target writes: max 30/minute per IP
target_rate_limiter = RateLimiter(requests=30, window=60)

# General read endpoints: max 120/minute per IP
read_rate_limiter = RateLimiter(requests=120, window=60)
