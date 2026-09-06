"""Domain aggregate-intelligence service.

Combines registration data, DNS signals, email-provider classification and IP
intelligence into a single response. Every field is sourced from an actual
provider; nothing is fabricated. Missing data is represented as None.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from app.core.config import Settings
from app.core.exceptions import (
    DNSLookupError,
    DNSNoDataError,
    DNSNXDomainError,
    DNSTimeoutError,
    WHOISUnavailableError,
)
from app.providers.dns.base import DNSProvider
from app.providers.email.mx_provider import detect_mx_provider
from app.providers.geoip.base import GeoIPProvider
from app.providers.hosting.asn_hosting import detect_hosting_provider_from_asn
from app.providers.hosting.parking import detect_parked_domain
from app.providers.whois.base import RegistryNotFoundError, RegistryRecord
from app.repositories.host_lists import (
    DisposableEmailRepository,
    HostListRepository,
    MaliciousHostRepository,
)
from app.services.whois_service import WhoIsService
from app.utils.domain import get_tld, is_risky_tld

logger = logging.getLogger(__name__)


class DomainService:
    def __init__(
        self,
        whois: WhoIsService,
        dns: DNSProvider,
        geoip: GeoIPProvider,
        disposable: DisposableEmailRepository,
        free_hosts: HostListRepository,
        risky_tlds: HostListRepository,
        malicious: MaliciousHostRepository,
        settings: Settings,
        metrics: Any | None = None,
    ) -> None:
        self._whois = whois
        self._dns = dns
        self._geoip = geoip
        self._disposable = disposable
        self._free_hosts = free_hosts
        self._risky_tlds = risky_tlds
        self._malicious = malicious
        self._settings = settings
        self._metrics = metrics

    async def lookup(self, domain: str) -> dict[str, Any]:
        start = time.perf_counter()
        # MX is an enrichment signal, not a prerequisite for domain lookup.
        # Domains are perfectly valid without an MX record, so NODATA/NXDOMAIN
        # must not abort the aggregate endpoint.
        has_mx: bool | None
        try:
            mx_hosts = await self._dns.get_mx_hosts(domain)
            usable_mx = [h for h in mx_hosts if h.hostname]
            has_mx = bool(usable_mx)
        except DNSNoDataError:
            # The DNS name exists but has no MX data.
            mx_hosts = []
            has_mx = False
        except DNSNXDomainError:
            # Registration can still be unavailable/available independently of
            # DNS state, so do not claim "no MX" from an NXDOMAIN.
            mx_hosts = []
            has_mx = None
        except (DNSTimeoutError, DNSLookupError):
            mx_hosts = []
            has_mx = None

        ns_hosts = await self._get_ns_hosts(domain)
        mx_provider = detect_mx_provider(
            [h.hostname for h in mx_hosts if h.hostname]
        )
        is_free = domain in self._free_hosts
        is_disposable = self._disposable.is_disposable(domain)
        is_malicious = self._malicious.is_malicious(domain)
        tld = get_tld(domain)
        risky = is_risky_tld(tld, self._risky_tlds.as_set()) if tld else None
        parked = detect_parked_domain([h.hostname for h in mx_hosts], ns_hosts)
        is_custom = self._is_custom_domain(domain, is_free, is_disposable)

        # Resolve a native IP and geolocate for hosting/country signals.
        ip: str | None = None
        hosting_provider: str | None = None
        country: str | None = None
        try:
            a_records = await self._dns.resolve_a(domain)
            if a_records:
                ip = a_records[0]
                geo = await self._geoip.lookup(ip)
                hosting_provider = detect_hosting_provider_from_asn(geo.asn_name)
                country = geo.country
        except Exception:
            logger.info("geoip/hosting lookup failed for %s", domain, exc_info=True)

        # Registration data.
        available: bool | None = None
        record: RegistryRecord | None = None
        try:
            record = await self._whois.lookup(domain)
        except RegistryNotFoundError:
            available = True
        except WHOISUnavailableError:
            available = None
            logger.warning("WHOIS data unavailable for %s", domain)
        else:
            available = False

        if self._metrics:
            self._metrics.observe_provider(
                "domain",
                "aggregate",
                (time.perf_counter() - start) * 1000,
                True,
            )

        result: dict[str, Any] = {
            "domain": domain,
            "available": available,
            "creation_date": record.creation_date if record else None,
            "expiration_date": record.expiration_date if record else None,
            "updated_date": record.updated_date if record else None,
            "registrar": record.registrar if record else None,
            "domain_status": list(record.status) if record else [],
            "age_days": (
                self._age_days(record.creation_date) if record and record.creation_date else None
            ),
            "has_mx": has_mx,
            "is_free_email_provider": is_free,
            "risky_tld": risky,
            "is_disposable_email_domain": is_disposable,
            "is_malicious": is_malicious,
            "mx_provider": mx_provider,
            "is_parked": parked,
            "ip": ip,
            "hosting_provider": hosting_provider,
            "country": country,
            "is_custom_domain": is_custom,
        }
        return result

    async def _get_ns_hosts(self, domain: str) -> list[str]:
        try:
            from app.providers.dns.models import DNSQuery

            result = await self._dns.lookup(DNSQuery(domain=domain, record_types=("NS",)))
        except Exception:
            return []
        return [r.value or "" for r in result.records if r.value]

    @staticmethod
    def _age_days(creation_ts: int) -> int | None:
        if not creation_ts:
            return None
        return max(0, int(time.time() - creation_ts) // 86400)

    @staticmethod
    def _is_custom_domain(domain: str, is_free: bool, is_disposable: bool) -> bool:
        """A custom domain means the operator controls its own mail hosting.

        Heuristic: the domain is NOT a well-known free provider and NOT a
        disposable host. This is a heuristic, so the result is a boolean based
        on available data.
        """
        return not (is_free or is_disposable)
