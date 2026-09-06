"""ip-api.com GeoIP provider.

Free (no API key), self-hostable, requests limited but adequate for low-traffic
deployments, and does not accept private addresses (which callers must handle
before invoking a provider).
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from app.core.exceptions import ProviderTimeoutError, ProviderUnavailableError
from app.providers.geoip.base import GeoIPResult

logger = logging.getLogger(__name__)

_HTTP_URL = "http://ip-api.com/json/{ip}"
_FIELDS = (
    "status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,"
    "isp,org,as,asname,reverse,query,proxy,hosting"
)


class IpApiGeoIPProvider:
    """Uses the free ip-api.com endpoint (plaintext: called over LAN; the
    endpoint rejects private IPs with status 'fail', which proxies fine here
    because callers block private addresses first)."""

    def __init__(self, client: httpx.AsyncClient, timeout: float = 5.0) -> None:
        self._client = client
        self._timeout = timeout

    async def lookup(self, ip: str) -> GeoIPResult:
        url = _HTTP_URL.format(ip=ip)
        try:
            resp = await self._client.get(url, params={"fields": _FIELDS}, timeout=self._timeout)
            resp.raise_for_status()
            data = resp.json()
        except httpx.TimeoutException as exc:
            raise ProviderTimeoutError(f"ip-api lookup timed out for {ip}") from exc
        except httpx.HTTPError as exc:
            raise ProviderUnavailableError(f"ip-api lookup failed: {exc}") from exc
        except ValueError as exc:
            raise ProviderUnavailableError("ip-api returned an invalid response") from exc

        if not isinstance(data, dict) or data.get("status") != "success":
            logger.warning("ip-api non-success response for %s", ip)
            return GeoIPResult()

        asn_raw: Any = data.get("as") or ""
        asn = asn_raw.strip().split(" ", 1)[0] if asn_raw else None
        asn_name = asn_raw.strip().split(" ", 1)[1] if asn_raw and " " in asn_raw else None

        result = GeoIPResult(
            country=data.get("country"),
            country_code=data.get("countryCode"),
            region=data.get("regionName"),
            region_code=data.get("region"),
            city=data.get("city"),
            zip=data.get("zip") or None,
            lat=data.get("lat"),
            lon=data.get("lon"),
            timezone=data.get("timezone"),
            isp=data.get("isp"),
            asn=asn,
            asn_name=asn_name,
            is_hosting=bool(data.get("hosting")),
        )
        # ip-api's `proxy` flag is not a Tor classifier. Do not relabel a
        # generic proxy as Tor; keep is_tor unknown unless a Tor-specific
        # source establishes it.
        return result
