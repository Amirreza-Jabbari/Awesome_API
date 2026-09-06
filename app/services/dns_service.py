from __future__ import annotations

import contextlib
import time
from typing import Any

from app.providers.dns.models import (
    DNSLookupResult,
    DNSQuery,
    DNSRecord,
    normalize_record_types,
)
from app.utils.domain import normalize_domain


class DNSService:
    """
    Application-level DNS service.

    Responsibilities:
        - canonical domain normalization
        - canonical record-type normalization
        - cache key construction
        - provider invocation
        - metrics
        - cache serialization/deserialization

    Provider-specific DNS behavior remains inside the provider layer.

    Constructor compatibility:
        DNSService(provider, cache, settings, metrics=metrics)

    The settings object is retained because the application dependency
    wiring and the other services use a shared settings-based construction
    contract.
    """

    def __init__(
        self,
        provider: Any,
        cache: Any | None,
        settings: Any,
        *,
        metrics: Any | None = None,
    ) -> None:
        self._provider = provider
        self._cache = cache
        self._settings = settings
        self._metrics = metrics

        # Keep a safe default while allowing the configuration object to
        # provide a DNS-specific cache TTL if one exists.
        #
        # The fallback keeps startup compatible even when the Settings
        # model does not define a dedicated DNS cache TTL.
        cache_ttl = getattr(
            settings,
            "dns_cache_ttl",
            getattr(settings, "cache_ttl", 300),
        )

        if not isinstance(cache_ttl, int):
            try:
                cache_ttl = int(cache_ttl)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    "DNS cache TTL must be an integer."
                ) from exc

        if cache_ttl <= 0:
            raise ValueError(
                "DNS cache TTL must be greater than zero."
            )

        self._cache_ttl = cache_ttl

    async def lookup(
        self,
        domain: str,
        record_types: tuple[str, ...] | list[str] | None = None,
    ) -> DNSLookupResult:
        """
        Perform a normalized, cached DNS lookup.
        """
        normalized_domain = normalize_domain(domain)

        types = normalize_record_types(record_types)

        cache_key = (
            f"dns:{normalized_domain}:"
            f"{','.join(types)}"
        )

        # ------------------------------------------------------------------
        # Cache lookup
        # ------------------------------------------------------------------
        if self._cache is not None:
            try:
                cached = await self._cache.get(cache_key)
            except Exception:
                # Cache is intentionally fail-open. A cache failure must
                # never prevent the DNS provider from being queried.
                cached = None

            if cached is not None:
                try:
                    return self._deserialize_result(cached)

                except (
                    TypeError,
                    ValueError,
                    KeyError,
                ):
                    # Corrupt/malformed cache data is treated as a miss.
                    with contextlib.suppress(Exception):
                        # Cache cleanup is best effort.
                        await self._cache.delete(cache_key)

        query = DNSQuery(
            domain=normalized_domain,
            record_types=types,
        )

        # ------------------------------------------------------------------
        # Provider lookup + metrics
        # ------------------------------------------------------------------
        started = time.perf_counter()

        try:
            result: DNSLookupResult = await self._provider.lookup(query)

        except Exception:
            elapsed = time.perf_counter() - started

            self._observe_provider_metric(
                success=False,
                latency=elapsed,
            )

            raise

        elapsed = time.perf_counter() - started

        self._observe_provider_metric(
            success=True,
            latency=elapsed,
        )

        # ------------------------------------------------------------------
        # Cache write
        # ------------------------------------------------------------------
        if self._cache is not None:
            payload = self._serialize_result(result)

            with contextlib.suppress(Exception):
                # Cache must never turn a successful DNS lookup into
                # a failed request.
                await self._cache.set(
                    cache_key,
                    payload,
                    self._cache_ttl,
                )

        return result

    async def lookup_mx(
        self,
        domain: str,
    ) -> DNSLookupResult:
        """
        Convenience method for MX-only lookups.
        """
        return await self.lookup(
            domain,
            ("MX",),
        )

    async def _lookup_provider(
        self,
        query: DNSQuery,
    ) -> DNSLookupResult:
        """
        Provider abstraction point.

        Retained for compatibility with implementations/tests that use
        a dedicated provider invocation method.
        """
        result: DNSLookupResult = await self._provider.lookup(query)
        return result

    @staticmethod
    def _serialize_result(
        result: DNSLookupResult,
    ) -> dict[str, Any]:
        """
        Convert a DNSLookupResult into the cache representation.
        """
        return {
            "domain": result.domain,
            "records": [
                record.to_dict()
                for record in result.records
            ],
        }

    @staticmethod
    def _deserialize_result(
        cached: Any,
    ) -> DNSLookupResult:
        """
        Reconstruct a DNSLookupResult from cached data.

        Cache data is treated as untrusted and is validated before
        constructing application models.
        """
        if not isinstance(cached, dict):
            raise ValueError(
                "Invalid cached DNS result."
            )

        domain = cached.get("domain")
        raw_records = cached.get("records")

        if not isinstance(domain, str):
            raise ValueError(
                "Invalid cached DNS domain."
            )

        if not isinstance(raw_records, list):
            raise ValueError(
                "Invalid cached DNS records."
            )

        records: list[DNSRecord] = []

        for item in raw_records:
            if not isinstance(item, dict):
                raise ValueError(
                    "Invalid cached DNS record."
                )

            try:
                record_type = item["record_type"]
                value = item["value"]

            except KeyError as exc:
                raise ValueError(
                    "Cached DNS record is missing required fields."
                ) from exc

            if not isinstance(record_type, str):
                raise ValueError(
                    "Invalid cached DNS record type."
                )

            if not isinstance(value, str):
                raise ValueError(
                    "Invalid cached DNS record value."
                )

            records.append(
                DNSRecord(
                    record_type=record_type,
                    value=value,
                    priority=item.get("priority"),
                    ttl=item.get("ttl"),
                    mname=item.get("mname"),
                    rname=item.get("rname"),
                    serial=item.get("serial"),
                    refresh=item.get("refresh"),
                    retry=item.get("retry"),
                    expire=item.get("expire"),
                    minimum=item.get("minimum"),
                )
            )

        return DNSLookupResult(
            domain=domain,
            records=records,
        )

    def _observe_provider_metric(
        self,
        *,
        success: bool,
        latency: float,
    ) -> None:
        """
        Record DNS provider metrics without allowing observability
        failures to affect the request.
        """
        if self._metrics is None:
            return

        try:
            if hasattr(
                self._metrics,
                "observe_dns_lookup",
            ):
                self._metrics.observe_dns_lookup(
                    success=success,
                    latency=latency,
                )

            elif hasattr(
                self._metrics,
                "observe",
            ):
                self._metrics.observe(
                    "dns_lookup",
                    latency,
                    success=success,
                )

        except Exception:
            # Metrics are non-critical infrastructure.
            pass
