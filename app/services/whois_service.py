"""WHOIS/RDAP application service with provider fallback."""

from __future__ import annotations

import logging
import time
from typing import Any

from app.core.config import Settings
from app.core.exceptions import WHOISUnavailableError
from app.providers.whois.base import RegistryNotFoundError, RegistryRecord, WhoIsProvider
from app.providers.whois.rdap_provider import RDAPProvider
from app.providers.whois.whois_provider import PythonWhoisProvider
from app.repositories.cache import Cache
from app.utils.domain import normalize_domain

logger = logging.getLogger(__name__)


class WhoIsService:
    """Registry-data lookup: RDAP first, WHOIS fallback.

    The RDAP provider is tried first because RDAP is structured and
    RFC-standardised; when it cannot serve a TLD the WHOIS provider is used.
    """

    def __init__(
        self,
        rdap: RDAPProvider,
        whois: PythonWhoisProvider,
        cache: Cache,
        settings: Settings,
        metrics: Any | None = None,
    ) -> None:
        self._rdap: WhoIsProvider = rdap
        self._whois: WhoIsProvider = whois
        self._cache = cache
        self._settings = settings
        self._metrics = metrics

    async def lookup(self, domain: str) -> RegistryRecord:
        normalized = normalize_domain(domain)
        key = f"whois:{normalized}"
        ttl = self._settings.whois_cache_ttl

        async def _fetch() -> dict[str, Any]:
            record = await self._detect(normalized)
            return self.record_to_dict(record)

        data = await self._cache.get_or_set(key, ttl, _fetch)
        return self._dict_to_record(data)

    async def _detect(self, domain: str) -> RegistryRecord:
        if self._metrics:
            start = time.perf_counter()
        try:
            record = await self._rdap.lookup(domain)
            if self._metrics:
                self._metrics.observe_provider(
                    "rdap",
                    "lookup",
                    (time.perf_counter() - start) * 1000,
                    True,
                )
            return record
        except RegistryNotFoundError:
            # Explicit registry 'not found' must pass through: it signals an
            # available domain, which differs from 'registry unavailable'.
            if self._metrics:
                self._metrics.observe_provider(
                    "rdap",
                    "lookup",
                    (time.perf_counter() - start) * 1000,
                    True,
                )
            raise
        except WHOISUnavailableError:
            if self._metrics:
                self._metrics.observe_provider(
                    "rdap",
                    "lookup",
                    (time.perf_counter() - start) * 1000,
                    False,
                )
            logger.info("RDAP fallback to WHOIS for %s", domain)

            start = time.perf_counter()
            try:
                record = await self._whois.lookup(domain)
                if self._metrics:
                    self._metrics.observe_provider(
                        "whois",
                        "lookup",
                        (time.perf_counter() - start) * 1000,
                        True,
                    )
                return record
            except WHOISUnavailableError as exc:
                if self._metrics:
                    self._metrics.observe_provider(
                        "whois",
                        "lookup",
                        (time.perf_counter() - start) * 1000,
                        False,
                    )
                raise WHOISUnavailableError(
                    f"No registration data is available for {domain}"
                ) from exc

    @staticmethod
    def record_to_dict(record: RegistryRecord) -> dict[str, Any]:
        return {
            "domain_name": record.domain_name,
            "registrar": record.registrar,
            "registrar_url": record.registrar_url,
            "whois_server": record.whois_server,
            "updated_date": record.updated_date,
            "creation_date": record.creation_date,
            "expiration_date": record.expiration_date,
            "name_servers": list(record.name_servers),
            "dnssec": record.dnssec,
            "status": list(record.status),
            "source": record.source,
        }

    @staticmethod
    def _dict_to_record(data: dict[str, Any]) -> RegistryRecord:
        return RegistryRecord(
            domain_name=data.get("domain_name"),
            registrar=data.get("registrar"),
            registrar_url=data.get("registrar_url"),
            whois_server=data.get("whois_server"),
            updated_date=data.get("updated_date"),
            creation_date=data.get("creation_date"),
            expiration_date=data.get("expiration_date"),
            name_servers=list(data.get("name_servers") or []),
            dnssec=data.get("dnssec"),
            status=list(data.get("status") or []),
            source=data.get("source"),
        )
