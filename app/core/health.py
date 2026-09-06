"""Safe liveness/readiness diagnostics."""
from __future__ import annotations

import time
from typing import Any

from app.core.config import Settings


class HealthService:
    """Centralized diagnostics with public-safe output."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def readiness(self, state: Any) -> dict[str, Any]:
        checks: dict[str, dict[str, Any]] = {}

        checks["application"] = {"status": "healthy"}
        checks["configuration"] = {
            "status": "healthy" if self._configuration_ok() else "unhealthy"
        }
        checks["dns"] = {
            "status": "healthy" if hasattr(state, "dns_provider") else "unhealthy"
        }

        cache = getattr(state, "cache", None)
        cache_backend = getattr(state, "cache_backend", "memory")
        if cache is None:
            checks["cache"] = {"status": "unhealthy"}
        elif cache_backend == "redis":
            started = time.perf_counter()
            try:
                if not await cache.ping():
                    raise RuntimeError("cache ping failed")
                checks["cache"] = {
                    "status": "healthy",
                    "latency_ms": round((time.perf_counter() - started) * 1000, 2),
                }
            except Exception:
                # Do not expose Redis hostnames, exception messages or topology.
                checks["cache"] = {"status": "degraded"}
        else:
            checks["cache"] = {"status": "healthy", "backend": "memory"}

        statuses = {item["status"] for item in checks.values()}
        overall = "unhealthy" if "unhealthy" in statuses else (
            "degraded" if "degraded" in statuses else "healthy"
        )
        return {"status": overall, "checks": checks}

    def _configuration_ok(self) -> bool:
        numeric = (
            self._settings.max_request_body_bytes,
            self._settings.max_json_body_bytes,
            self._settings.max_response_body_bytes,
            self._settings.max_json_depth,
            self._settings.max_json_nodes,
            self._settings.max_parser_nodes,
        )
        return all(value > 0 for value in numeric)
