"""Configurable TTL caching.

Two implementations are provided behind one interface:

* ``MemoryCache`` - in-process TTL cache suitable for single-instance and
  development deployments.
* ``RedisCache`` - Redis-backed cache for multi-instance deployments.

Values are expected to be JSON-serializable. The cache is used for slow
lookups (DNS, RDAP/WHOIS, IP intelligence) and deliberately NEVER for
password generation or user-specific/sensitive data.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Awaitable, Callable
from typing import Any, Protocol, TypeVar, cast

T = TypeVar("T")

logger = logging.getLogger(__name__)


class MetricCollector(Protocol):
    """Minimal cache metrics interface."""

    def observe_cache(self, hit: bool) -> None:
        ...


class NoopMetrics:
    """No-op cache metrics implementation."""

    def observe_cache(self, hit: bool) -> None:
        del hit


class Cache(Protocol):
    """Common asynchronous cache interface."""

    async def get(self, key: str) -> Any | None:
        ...

    async def set(self, key: str, value: Any, ttl: int) -> None:
        ...

    async def delete(self, key: str) -> None:
        ...

    async def ping(self) -> bool:
        return True

    async def get_or_set(
        self,
        key: str,
        ttl: int,
        factory: Callable[[], Awaitable[T]],
    ) -> T:
        ...


class MemoryCache:
    """Thread-safe in-process TTL cache.

    Cache values are stored in memory and therefore are local to the current
    application process.

    ``get_or_set`` additionally uses per-key asyncio locks to prevent multiple
    concurrent callers from executing the same expensive factory operation
    after a cache miss.
    """

    def __init__(self, max_entries: int = 10_000, metrics: MetricCollector | None = None) -> None:
        self._store: dict[str, tuple[float, Any]] = {}
        self._max_entries = max(1, max_entries)
        self._metrics = metrics or NoopMetrics()
        self._lock = threading.Lock()

        # Locks are created lazily because the cache may be instantiated before
        # the application's asyncio event loop exists.
        self._async_locks: dict[str, Any] = {}
        self._async_locks_guard = threading.Lock()

    @staticmethod
    def _validate_ttl(ttl: int) -> int:
        if isinstance(ttl, bool) or not isinstance(ttl, int):
            raise TypeError("Cache TTL must be an integer")

        if ttl <= 0:
            raise ValueError("Cache TTL must be greater than zero")

        return ttl

    def _get_async_lock(self, key: str) -> Any:
        """Return/create a per-key asyncio lock.

        The import is intentionally local so the synchronous cache data
        structure remains independent from event-loop initialization.
        """
        import asyncio

        with self._async_locks_guard:
            lock = self._async_locks.get(key)

            if lock is None:
                lock = asyncio.Lock()
                self._async_locks[key] = lock

            return lock

    def _get_raw(self, key: str) -> Any | None:
        now = time.monotonic()
        with self._lock:
            item = self._store.get(key)
            if item is None:
                return None
            expires_at, value = item
            if expires_at <= now:
                self._store.pop(key, None)
                return None
            return value

    async def get(self, key: str) -> Any | None:
        value = self._get_raw(key)
        self._metrics.observe_cache(value is not None)
        return value

    async def set(
        self,
        key: str,
        value: Any,
        ttl: int,
    ) -> None:
        """Store a value for ``ttl`` seconds."""
        ttl = self._validate_ttl(ttl)

        with self._lock:
            if len(self._store) >= self._max_entries and key not in self._store:
                oldest_key = min(self._store, key=lambda k: self._store[k][0])
                self._store.pop(oldest_key, None)
            self._store[key] = (
                time.monotonic() + ttl,
                value,
            )

    async def delete(self, key: str) -> None:
        """Delete a cache entry if it exists."""
        with self._lock:
            self._store.pop(key, None)

    async def ping(self) -> bool:
        return True

    async def get_or_set(
        self,
        key: str,
        ttl: int,
        factory: Callable[[], Awaitable[T]],
    ) -> T:
        """Return a cached value or atomically populate the key per process."""

        cached = await self.get(key)

        if cached is not None:
            return cast(T, cached)

        lock = self._get_async_lock(key)

        async with lock:
            # Another coroutine may have populated the cache while we were
            # waiting for the per-key lock.
            cached = self._get_raw(key)
            if cached is not None:
                return cast(T, cached)

            value = await factory()
            await self.set(key, value, ttl)

            return value


class RedisCache:
    """Redis-backed TTL cache.

    Redis failures are deliberately fail-open:
    cache outages do not make the underlying DNS/provider operation fail.

    Values are serialized as JSON.
    """

    def __init__(self, url: str) -> None:
        if not isinstance(url, str) or not url.strip():
            raise ValueError("Redis cache URL cannot be empty")

        self._url = url.strip()
        self._redis: Any = None

    @staticmethod
    def _validate_ttl(ttl: int) -> int:
        if isinstance(ttl, bool) or not isinstance(ttl, int):
            raise TypeError("Cache TTL must be an integer")

        if ttl <= 0:
            raise ValueError("Cache TTL must be greater than zero")

        return ttl

    async def _ensure(self) -> Any:
        """Lazily initialize the Redis client."""
        if self._redis is None:
            import redis.asyncio as aioredis

            self._redis = aioredis.from_url(  # type: ignore[no-untyped-call]
                self._url,
                encoding="utf-8",
                decode_responses=True,
            )

        return self._redis

    async def ping(self) -> bool:
        try:
            client = await self._ensure()
            return bool(await client.ping())
        except Exception:
            return False

    async def get(self, key: str) -> Any | None:
        """Read and JSON-decode a cached value.

        Redis failures and corrupt entries are treated as cache misses.
        """
        try:
            client = await self._ensure()
            raw = await client.get(key)

        except Exception:
            logger.warning(
                "Redis cache get failed",
            )
            return None

        if raw is None:
            return None

        try:
            return json.loads(raw)

        except (TypeError, ValueError, json.JSONDecodeError):
            logger.warning(
                "Redis cache entry contains invalid JSON",
            )

            # Best-effort cleanup. A corrupt value should not repeatedly
            # poison the same cache key.
            try:
                await client.delete(key)
            except Exception:
                logger.debug(
                    "Failed to remove corrupt Redis cache entry",
                )

            return None

    async def set(
        self,
        key: str,
        value: Any,
        ttl: int,
    ) -> None:
        """Store a JSON-serializable value in Redis."""
        ttl = self._validate_ttl(ttl)

        try:
            payload = json.dumps(
                value,
                ensure_ascii=False,
                separators=(",", ":"),
            )
        except (TypeError, ValueError):
            logger.warning(
                "Redis cache value is not JSON serializable",
            )
            return

        try:
            client = await self._ensure()
            await client.set(
                key,
                payload,
                ex=ttl,
            )

        except Exception:
            logger.warning(
                "Redis cache set failed",
            )

    async def delete(self, key: str) -> None:
        """Delete a Redis cache entry."""
        try:
            client = await self._ensure()
            await client.delete(key)

        except Exception:
            logger.warning(
                "Redis cache delete failed",
            )

    async def get_or_set(
        self,
        key: str,
        ttl: int,
        factory: Callable[[], Awaitable[T]],
    ) -> T:
        """Return a cached value or populate it.

        Redis remains fail-open. Distributed request coalescing is intentionally
        not implemented here because doing it correctly requires a lease-based
        distributed lock with ownership tokens and failure handling.
        """
        cached = await self.get(key)

        if cached is not None:
            return cast(T, cached)

        value = await factory()
        await self.set(key, value, ttl)

        return value

    async def close(self) -> None:
        """Close the Redis client if it has been initialized."""
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


class NullCache:
    """Cache implementation that never stores anything."""

    async def ping(self) -> bool:
        return True

    async def get(self, key: str) -> Any | None:
        del key
        return None

    async def set(
        self,
        key: str,
        value: Any,
        ttl: int,
    ) -> None:
        del key, value, ttl

    async def delete(self, key: str) -> None:
        del key

    async def get_or_set(
        self,
        key: str,
        ttl: int,
        factory: Callable[[], Awaitable[T]],
    ) -> T:
        del key, ttl
        return await factory()
