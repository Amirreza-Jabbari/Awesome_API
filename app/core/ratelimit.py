"""Configurable fixed-window rate limiting with local and Redis backends."""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any, Protocol

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    allowed: bool
    limit: int
    remaining: int
    reset_after: int


class RateLimiter(Protocol):
    async def check(self, key: str, limit: int, window: int) -> RateLimitDecision:
        ...

    async def allow(self, key: str, limit: int, window: int) -> bool:
        ...


class MemoryRateLimiter:
    """In-process fixed-window limiter with bounded state cleanup."""

    def __init__(self, max_keys: int = 100_000) -> None:
        self._counts: dict[str, tuple[int, float]] = {}
        self._lock = threading.Lock()
        self._operations = 0
        self._max_keys = max(1, max_keys)

    async def check(self, key: str, limit: int, window: int) -> RateLimitDecision:
        if limit <= 0 or window <= 0:
            return RateLimitDecision(False, max(limit, 0), 0, 0)
        now = time.monotonic()
        with self._lock:
            self._operations += 1
            if self._operations % 256 == 0 or len(self._counts) > self._max_keys:
                cutoff = now - window
                self._counts = {k: v for k, v in self._counts.items() if v[1] > cutoff}
            # Enforce the hard state bound even when the cleanup interval has not fired.
            if key not in self._counts and len(self._counts) >= self._max_keys:
                oldest_key = min(self._counts, key=lambda k: self._counts[k][1])
                self._counts.pop(oldest_key, None)

            count, window_start = self._counts.get(key, (0, now))
            if now - window_start >= window:
                count, window_start = 0, now
            reset = max(1, int(window - (now - window_start) + 0.999))
            if count >= limit:
                self._counts[key] = (count, window_start)
                return RateLimitDecision(False, limit, 0, reset)
            count += 1
            self._counts[key] = (count, window_start)
            return RateLimitDecision(True, limit, max(0, limit - count), reset)

    async def allow(self, key: str, limit: int, window: int) -> bool:
        return (await self.check(key, limit, window)).allowed


class RedisRateLimiter:
    """Redis fixed-window limiter using an atomic Lua script for count/TTL."""

    _SCRIPT = """
    local count = redis.call('INCR', KEYS[1])
    if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
    local ttl = redis.call('TTL', KEYS[1])
    return {count, ttl}
    """

    def __init__(self, url: str) -> None:
        self._url = url
        self._redis: Any = None
        self._script: Any = None

    async def _ensure(self) -> Any:
        if self._redis is None:
            import redis.asyncio as aioredis
            self._redis = aioredis.from_url(self._url, decode_responses=True)
        return self._redis

    async def check(self, key: str, limit: int, window: int) -> RateLimitDecision:
        if limit <= 0 or window <= 0:
            return RateLimitDecision(False, max(limit, 0), 0, 0)
        try:
            client = await self._ensure()
            if self._script is None:
                self._script = client.register_script(self._SCRIPT)
            count, ttl = await self._script(keys=[key], args=[window])
            count = int(count)
            ttl = max(1, int(ttl))
            return RateLimitDecision(count <= limit, limit, max(0, limit - count), ttl)
        except Exception:
            # Availability wins over strict throttling during a Redis outage.
            logger.warning("redis rate limiter unavailable; allowing request")
            return RateLimitDecision(True, limit, max(0, limit - 1), window)

    async def allow(self, key: str, limit: int, window: int) -> bool:
        return (await self.check(key, limit, window)).allowed

    async def close(self) -> None:
        if self._redis is None:
            return
        try:
            close_method = getattr(self._redis, "aclose", None)
            if close_method is not None:
                await close_method()
            else:
                await self._redis.close()
        finally:
            self._redis = None
            self._script = None


class NullRateLimiter:
    async def check(self, key: str, limit: int, window: int) -> RateLimitDecision:
        del key, window
        return RateLimitDecision(True, max(0, limit), max(0, limit), 0)

    async def allow(self, key: str, limit: int, window: int) -> bool:
        return (await self.check(key, limit, window)).allowed


def build_rate_limiter(
    enabled: bool,
    redis_url: str | None = None,
    max_keys: int = 100_000,
) -> MemoryRateLimiter | RedisRateLimiter | NullRateLimiter:
    if not enabled:
        return NullRateLimiter()
    if redis_url:
        return RedisRateLimiter(redis_url)
    return MemoryRateLimiter(max_keys=max_keys)
