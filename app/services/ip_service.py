"""IP lookup application service.

Validates and classifies addresses locally (never sending private/loopback/
reserved addresses to external providers), then optionally queries configured
GeoIP/IP-intelligence providers for fields they can actually establish.
"""

from __future__ import annotations

import logging
from typing import Any

from app.core.config import Settings
from app.providers.geoip.base import GeoIPProvider
from app.providers.ipintel.base import IPIntelligenceProvider
from app.repositories.cache import Cache
from app.utils.ip import classify, compact_ipv6, is_bogon, is_valid_ip

logger = logging.getLogger(__name__)


class IPLookupError(ValueError):
    pass


class IPService:
    def __init__(
        self,
        geoip: GeoIPProvider,
        intel: IPIntelligenceProvider,
        cache: Cache,
        settings: Settings,
        metrics: Any | None = None,
    ) -> None:
        self._geoip = geoip
        self._intel = intel
        self._cache = cache
        self._settings = settings
        self._metrics = metrics

    async def lookup(self, ip: str) -> dict[str, Any]:
        if not is_valid_ip(ip):
            raise IPLookupError("Invalid IP address.")
        ip = compact_ipv6(ip)

        cls = classify(ip)
        base = {
            "address": ip,
            "ip_version": 4 if cls["is_ipv4"] else 6,
            "is_valid": True,
            "is_private": cls["is_private"],
            "is_loopback": cls["is_loopback"],
            "is_multicast": cls["is_multicast"],
            "is_bogon": is_bogon(ip),
        }

        # Never send private/internal addresses to external providers.
        if not cls["is_global"] and (
            cls["is_private"] or cls["is_loopback"] or cls["is_multicast"] or cls["is_reserved"]
        ):
            return {
                **base,
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
                "is_datacenter": None,
                "is_hosting": None,
                "is_tor": None,
                "is_vpn": None,
                "is_icloud_relay": None,
                "is_abuser": None,
                "threat_level": None,
                "asn": None,
                "asn_name": None,
                "route": None,
                "abuse_email": None,
            }

        key = f"ip:{ip}"
        ttl = self._settings.ip_lookup_cache_ttl

        async def _fetch() -> dict[str, Any]:
            geo = await self._geoip.lookup(ip)
            intel = await self._intel.lookup(ip)
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
                "is_datacenter": (
                    intel.is_datacenter if intel.is_datacenter is not None else geo.is_datacenter
                ),
                "is_hosting": (
                    intel.is_hosting if intel.is_hosting is not None else geo.is_hosting
                ),
                "is_tor": intel.is_tor if intel.is_tor is not None else geo.is_tor,
                "is_vpn": (
                    intel.is_vpn if intel.is_vpn is not None else geo.is_vpn
                ),
                "is_icloud_relay": (
                    intel.is_icloud_relay
                    if intel.is_icloud_relay is not None
                    else geo.is_icloud_relay
                ),
                "is_abuser": (
                    intel.is_abuser if intel.is_abuser is not None else geo.is_abuser
                ),
                "threat_level": (
                    intel.threat_level
                    if intel.threat_level is not None
                    else geo.threat_level
                ),
                "asn": geo.asn,
                "asn_name": geo.asn_name,
                "route": geo.route,
                "abuse_email": geo.abuse_email,
            }

        try:
            data = await self._cache.get_or_set(key, ttl, _fetch)
        except Exception as exc:
            logger.warning("IP intelligence lookup failed for %s: %s", ip, exc)
            data = {
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
                "is_datacenter": None,
                "is_hosting": None,
                "is_tor": None,
                "is_vpn": None,
                "is_icloud_relay": None,
                "is_abuser": None,
                "threat_level": None,
                "asn": None,
                "asn_name": None,
                "route": None,
                "abuse_email": None,
            }

        return {**base, **data}
