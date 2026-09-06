"""Free, no-key IP intelligence provider.

This provider deliberately composes public endpoints instead of depending on a
single commercial/keyed service:

* ipwho.is      -> geolocation, timezone, ISP/organization/ASN
* ipapi.is      -> hosting/Tor/VPN/proxy/abuse signals and ASN
* rdap.org      -> network (route) and abuse-contact information

All three are best-effort. A failure in one source does not erase data obtained
from the others. The application cache in ``IPService`` prevents repeated
lookups for the same address from continuously consuming public quotas.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from typing import Any

import httpx

from app.core.exceptions import ProviderTimeoutError, ProviderUnavailableError
from app.providers.geoip.base import GeoIPResult

logger = logging.getLogger(__name__)

IPWHO_URL = "https://ipwho.is/{ip}"
IPAPI_IS_URL = "https://api.ipapi.is/"
RDAP_IP_URL = "https://rdap.org/ip/{ip}"


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes"}:
            return True
        if lowered in {"false", "0", "no"}:
            return False
    return None


def _asn(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, int):
        return f"AS{value}"
    text = str(value).strip()
    if not text:
        return None
    return text if text.upper().startswith("AS") else f"AS{text}"


def _route_from_rdap(data: dict[str, Any], ip: str) -> str | None:
    cidrs = data.get("cidr0_cidrs")
    if isinstance(cidrs, list):
        for item in cidrs:
            if isinstance(item, dict):
                prefix = item.get("v4prefix") or item.get("v6prefix")
                length = item.get("length")
                if prefix is not None and length is not None:
                    return f"{prefix}/{int(length)}"

    start = _text(data.get("startAddress"))
    end = _text(data.get("endAddress"))
    if not start or not end:
        return None

    try:
        start_ip = ipaddress.ip_address(start)
        end_ip = ipaddress.ip_address(end)
        if start_ip.version != end_ip.version:
            return None
        networks = list(ipaddress.summarize_address_range(start_ip, end_ip))
        return str(networks[0])
    except ValueError:
        return None


def _find_abuse_email(data: dict[str, Any]) -> str | None:
    def walk(value: Any) -> str | None:
        if isinstance(value, dict):
            roles = value.get("roles")
            if isinstance(roles, list) and "abuse" in roles:
                vcard = value.get("vcardArray")
                email = _email_from_vcard(vcard)
                if email:
                    return email
            for child in value.values():
                found = walk(child)
                if found:
                    return found
        elif isinstance(value, list):
            for child in value:
                found = walk(child)
                if found:
                    return found
        return None

    return walk(data)


def _email_from_vcard(vcard: Any) -> str | None:
    if not isinstance(vcard, list) or len(vcard) != 2 or not isinstance(vcard[1], list):
        return None
    for item in vcard[1]:
        if not isinstance(item, list) or len(item) < 4 or item[0] != "email":
            continue
        value = item[3]
        if isinstance(value, str) and "@" in value:
            return value.strip()
    return None


class FreeIPIntelligenceProvider:
    """Best-effort IP intelligence using public, no-key services."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        timeout: float = 6.0,
    ) -> None:
        self._client = client
        self._timeout = timeout

    async def _get_json(self, url: str, **kwargs: Any) -> dict[str, Any]:
        try:
            response = await self._client.get(url, timeout=self._timeout, **kwargs)
            response.raise_for_status()
            data = response.json()
        except httpx.TimeoutException as exc:
            raise ProviderTimeoutError("Free IP intelligence provider timed out") from exc
        except httpx.HTTPError as exc:
            raise ProviderUnavailableError(f"Free IP intelligence provider failed: {exc}") from exc
        except ValueError as exc:
            raise ProviderUnavailableError(
                "Free IP intelligence provider returned invalid JSON"
            ) from exc

        if not isinstance(data, dict):
            raise ProviderUnavailableError("Free IP intelligence provider returned invalid data")
        return data

    async def _safe(self, name: str, url: str, **kwargs: Any) -> dict[str, Any]:
        try:
            return await self._get_json(url, **kwargs)
        except Exception as exc:
            logger.info("%s lookup failed: %s", name, exc)
            return {}

    async def lookup(self, ip: str) -> GeoIPResult:
        geo_task = self._safe("ipwho.is", IPWHO_URL.format(ip=ip))
        security_task = self._safe("ipapi.is", IPAPI_IS_URL, params={"q": ip})
        rdap_task = self._safe("IP RDAP", RDAP_IP_URL.format(ip=ip))

        geo, security, rdap = await asyncio.gather(
            geo_task,
            security_task,
            rdap_task,
        )

        if not geo and not security and not rdap:
            raise ProviderUnavailableError("All free IP intelligence providers failed")

        connection = geo.get("connection") or {}
        timezone = geo.get("timezone") or {}
        security_block = geo.get("security") or {}

        # Anonymous ipapi.is intentionally returns a compact response. These
        # fields are available without a key and are the authoritative source
        # for the security signals exposed here.
        result = GeoIPResult(
            country=_text(geo.get("country")),
            country_code=_text(geo.get("country_code")) or _text(security.get("cc")),
            region=_text(geo.get("region")),
            region_code=_text(geo.get("region_code")),
            city=_text(geo.get("city")),
            zip=_text(geo.get("postal")),
            lat=geo.get("latitude"),
            lon=geo.get("longitude"),
            timezone=_text(timezone.get("id")),
            isp=_text(connection.get("isp")) or _text(security.get("asn_org")),
            asn=_asn(connection.get("asn")) or _asn(security.get("asn_num")),
            asn_name=_text(connection.get("org")) or _text(security.get("company_name")),
            route=_route_from_rdap(rdap, ip),
            abuse_email=_find_abuse_email(rdap),
            is_datacenter=_bool(security.get("is_datacenter")),
            is_hosting=_bool(security.get("is_datacenter")),
            is_tor=_bool(security.get("is_tor")) if security else _bool(security_block.get("tor")),
            is_vpn=_bool(security.get("is_vpn")) if security else _bool(security_block.get("vpn")),
            is_icloud_relay=_bool(security_block.get("relay")),
            is_abuser=_bool(security.get("is_abuser")),
        )

        if result.lat is not None:
            try:
                result.lat = float(result.lat)
            except (TypeError, ValueError):
                result.lat = None
        if result.lon is not None:
            try:
                result.lon = float(result.lon)
            except (TypeError, ValueError):
                result.lon = None

        # ipwho.is calls this flag "hosting"; use it only as a fallback because
        # ipapi.is has the dedicated datacenter field on its anonymous tier.
        if result.is_hosting is None:
            result.is_hosting = _bool(security_block.get("hosting"))
        if result.is_datacenter is None:
            result.is_datacenter = result.is_hosting

        return result
