"""MX lookup application service."""

from __future__ import annotations

import logging
from typing import Any

from app.core.config import Settings
from app.providers.dns.base import DNSProvider
from app.providers.dns.models import MXData
from app.repositories.cache import Cache
from app.utils.domain import normalize_domain

logger = logging.getLogger(__name__)


class MXService:
    def __init__(
        self,
        provider: DNSProvider,
        cache: Cache,
        settings: Settings,
        metrics: Any | None = None,
    ) -> None:
        self._provider = provider
        self._cache = cache
        self._settings = settings
        self._metrics = metrics

    async def lookup(self, domain: str) -> tuple[str, list[MXData]]:
        normalized = normalize_domain(domain)
        key = f"mx:{normalized}"
        ttl = self._settings.dns_cache_ttl

        async def _fetch() -> list[dict[str, Any]]:
            hosts = await self._provider.get_mx_hosts(normalized)
            return [
                {"priority": h.priority, "hostname": h.hostname}
                for h in hosts
                if h.hostname
            ]

        data = await self._cache.get_or_set(key, ttl, _fetch)
        hosts = [
            MXData(priority=int(item["priority"]), hostname=str(item["hostname"]))
            for item in data
            if isinstance(item, dict) and item.get("hostname")
        ]
        hosts.sort(key=lambda m: (m.priority, m.hostname))
        return normalized, hosts
