"""GeoIP provider abstraction and result model."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from app.core.exceptions import ProviderConfigurationError


@dataclass(slots=True)
class GeoIPResult:
    """Geolocation fields. Unknown values are None (never fabricated)."""

    country: str | None = None
    country_code: str | None = None
    region: str | None = None
    region_code: str | None = None
    city: str | None = None
    zip: str | None = None
    lat: float | None = None
    lon: float | None = None
    timezone: str | None = None
    isp: str | None = None
    asn: str | None = None
    asn_name: str | None = None
    route: str | None = None
    abuse_email: str | None = None
    is_datacenter: bool | None = None
    is_hosting: bool | None = None
    is_tor: bool | None = None
    is_vpn: bool | None = None
    is_icloud_relay: bool | None = None
    is_abuser: bool | None = None
    threat_level: str | None = None


class GeoIPProvider(Protocol):
    async def lookup(self, ip: str) -> GeoIPResult:
        """Look up geolocation/intelligence for an IP string.

        Providers must raise ProviderUnavailableError on failure so the caller
        can degrade gracefully.
        """
        ...


class MaxMindUnavailableError(ProviderConfigurationError):
    pass
