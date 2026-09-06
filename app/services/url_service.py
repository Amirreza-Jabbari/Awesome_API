"""URL lookup application service.

Pipeline: URL parsing -> domain extraction -> domain validation -> DNS
resolution -> (optional) IP intelligence.

The URL is never fetched over HTTP for a lookup; only DNS + IP metadata is
used, so there is no SSRF risk from scanning arbitrary URL content. Domains
that resolve to private/internal targets are still reported (they are simply
data), unlike the webpage fetcher which actively blocks them.
"""

from __future__ import annotations

import logging
from typing import Any

from app.core.config import Settings
from app.core.exceptions import SSRFBlockedError
from app.providers.dns.base import DNSProvider
from app.providers.geoip.base import GeoIPProvider
from app.repositories.cache import Cache
from app.utils.ip import is_address_blocked, parse_ip
from app.utils.url import extract_host, normalize_url

logger = logging.getLogger(__name__)


class URLService:
    def __init__(
        self,
        dns: DNSProvider,
        geoip: GeoIPProvider,
        cache: Cache,
        settings: Settings,
        metrics: Any | None = None,
    ) -> None:
        self._dns = dns
        self._geoip = geoip
        self._cache = cache
        self._settings = settings
        self._metrics = metrics

    async def lookup(self, raw_url: str) -> dict[str, Any]:
        url = normalize_url(raw_url)
        host = extract_host(url)

        # Literal-IP hosts are validated directly; they cannot be DNS-resolved
        # as such but we still report basic metadata without contacting anyone.
        addrs: list[str] = []
        try:
            parsed_ip = parse_ip(host)
            addrs = [str(parsed_ip)]
        except ValueError:
            addrs = await self._dns.resolve_a_aaaa(host)

        if not addrs:
            raise SSRFBlockedError(f"Could not resolve host: {host}")

        # For URL *lookup* (read-only intelligence) we still report info for
        # private targets, but never route data through an external provider.
        public_addrs = [a for a in addrs if not is_address_blocked(a)]

        result: dict[str, Any] = {
            "url": url,
            "is_valid": True,
            "ip": addrs[0],
            "country": None,
            "country_code": None,
            "region": None,
            "region_code": None,
            "city": None,
            "zip": None,
            "lat": None,
            "lon": None,
            "timezone": None,
            "isp": None,
        }

        if not public_addrs:
            return result

        async def fetch_geo() -> dict[str, Any]:
            last_error: Exception | None = None
            for address in public_addrs:
                try:
                    geo = await self._geoip.lookup(address)
                    return {
                        "country": geo.country,
                        "country_code": geo.country_code,
                        "region": geo.region,
                        "region_code": geo.region_code,
                        "city": geo.city,
                        "zip": geo.zip,
                        "lat": geo.lat,
                        "lon": geo.lon,
                        "timezone": geo.timezone,
                        "isp": geo.isp,
                    }
                except Exception as exc:
                    last_error = exc
                    logger.info("URL GeoIP lookup failed for %s: %s", address, exc)
            if last_error is not None:
                raise last_error
            return {}

        # Cache IP enrichment rather than the complete URL. This avoids
        # duplicating identical intelligence for many paths/query strings.
        cache_key = f"urlgeo:{public_addrs[0]}"
        try:
            geo_data = await self._cache.get_or_set(
                cache_key,
                self._settings.ip_lookup_cache_ttl,
                fetch_geo,
            )
        except Exception as exc:
            # URL validation/DNS resolution succeeded. Provider outages should
            # not turn a valid URL lookup into a 500 response.
            logger.warning("URL GeoIP enrichment failed: %s", exc)
            geo_data = {}

        result.update(geo_data)
        return result
