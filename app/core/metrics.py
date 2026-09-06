"""Optional Prometheus-style metrics collection.

When ``METRICS_ENABLED`` is false, a no-op collector keeps instrumentation
points call-safe with zero overhead. When enabled, counters/histograms are
registered with the prometheus client and exposed via the ``/metrics`` route.
"""

from __future__ import annotations

from typing import Any

from app.core.config import Settings

_counter = Any
_histogram = Any


class NoopMetrics:
    def inc_request(self, status: int, path: str, method: str) -> None:
        del status, path, method

    def observe_duration(self, path: str, method: str, duration_ms: float) -> None:
        del path, method, duration_ms

    def inc_error(self, code: str) -> None:
        del code

    def observe_provider(
        self,
        provider: str,
        operation: str,
        duration_ms: float,
        success: bool,
    ) -> None:
        del provider, operation, duration_ms, success

    def observe_cache(self, hit: bool) -> None:
        del hit

    def inc_rate_limited(self) -> None:
        pass

    def inc_security_rejection(self, reason: str) -> None:
        del reason

    def inc_upstream(self, provider: str, success: bool) -> None:
        del provider, success


class PrometheusMetrics:
    """Prometheus client backed metrics collector."""

    def __init__(self) -> None:
        from prometheus_client import Counter, Histogram

        self._requests = Counter(
            "api_requests_total",
            "Total HTTP requests",
            ["method", "path", "status"],
        )
        self._duration = Histogram(
            "api_request_duration_ms",
            "HTTP request duration in milliseconds",
            ["method", "path"],
            buckets=(5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000),
        )
        self._errors = Counter(
            "api_errors_total",
            "Application errors by code",
            ["code"],
        )
        self._provider = Histogram(
            "api_provider_duration_ms",
            "Provider call duration in milliseconds",
            ["provider", "operation", "success"],
            buckets=(1, 5, 10, 25, 50, 100, 250, 500, 1000, 3000),
        )
        self._cache_hits = Counter("api_cache_hits_total", "Cache hits")
        self._cache_misses = Counter("api_cache_misses_total", "Cache misses")
        self._rate_limited = Counter("api_rate_limited_total", "Rate limited requests")
        self._security_rejections = Counter(
            "api_security_rejections_total", "Security policy rejections", ["reason"]
        )
        self._upstream_requests = Counter(
            "api_upstream_requests_total", "Upstream requests", ["provider", "success"]
        )

    def inc_request(self, status: int, path: str, method: str) -> None:
        self._requests.labels(method, path, str(status)).inc()

    def observe_duration(self, path: str, method: str, duration_ms: float) -> None:
        self._duration.labels(method, path).observe(duration_ms)

    def inc_error(self, code: str) -> None:
        self._errors.labels(code).inc()

    def observe_provider(
        self,
        provider: str,
        operation: str,
        duration_ms: float,
        success: bool,
    ) -> None:
        self._provider.labels(provider, operation, str(success)).observe(duration_ms)

    def observe_cache(self, hit: bool) -> None:
        if hit:
            self._cache_hits.inc()
        else:
            self._cache_misses.inc()

    def inc_rate_limited(self) -> None:
        self._rate_limited.inc()

    def inc_security_rejection(self, reason: str) -> None:
        self._security_rejections.labels(reason).inc()

    def inc_upstream(self, provider: str, success: bool) -> None:
        self._upstream_requests.labels(provider, str(success)).inc()


def build_metrics(settings: Settings) -> NoopMetrics | PrometheusMetrics:
    if settings.metrics_enabled:
        return PrometheusMetrics()
    return NoopMetrics()
