"""RDAP provider using the IANA bootstrap registry.

Fetches the IANA RDAP bootstrap file to map TLDs -> base URLs (cached in
memory with a TTL), then queries the registry. When a domain has no RDAP
coverage this provider raises :class:`WHOISProviderError` so callers can fall
back to a WHOIS provider.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime
from typing import Any

import httpx

from app.core.config import Settings
from app.core.exceptions import ResourceLimitError
from app.providers.web.ssrf import SSRFGuard, pin_address, unpin_address
from app.providers.whois.base import RegistryNotFoundError, RegistryRecord, WHOISProviderError
from app.utils.domain import get_registrable_domain, normalize_domain

logger = logging.getLogger(__name__)

IANA_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
BOOTSTRAP_TTL = 86400  # 24h
# Registries communicate times in UTC per RFC 7483.
_TIMESTAMP_MAX = 8_535_888_000  # year 2240 upper bound guard


class RDAPProvider:
    """RDAP-over-HTTP provider with IANA bootstrap discovery."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        settings: Settings,
        guard: SSRFGuard | None = None,
    ) -> None:
        self._client = client
        self._timeout = settings.rdap_timeout
        self._max_response_bytes = settings.max_upstream_response_bytes
        self._guard = guard
        self._bootstrap: dict[str, list[str]] = {}
        self._bootstrap_fetched_at = 0.0

    async def _get_json(self, url: str) -> Any:
        parsed = httpx.URL(url)
        hostname = parsed.host
        token = None
        if self._guard is not None and hostname:
            addresses = await self._guard.resolve_and_check(hostname)
            token = pin_address(hostname, addresses[0])
        try:
            async with self._client.stream(
                "GET", url, timeout=self._timeout, follow_redirects=False
            ) as response:
                if response.status_code >= 300:
                    raise WHOISProviderError("RDAP upstream returned an unexpected redirect/status.")
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > self._max_response_bytes:
                        raise ResourceLimitError("RDAP response exceeds the configured size limit.")
                response.raise_for_status()
                import json
                return json.loads(bytes(body))
        finally:
            if token is not None:
                unpin_address(token)

    async def _get_bootstrap(self) -> dict[str, list[str]]:
        now = time.monotonic()
        if self._bootstrap and (now - self._bootstrap_fetched_at) < BOOTSTRAP_TTL:
            return self._bootstrap
        try:
            data = await self._get_json(IANA_BOOTSTRAP_URL)
            if not isinstance(data, dict):
                raise ValueError("invalid RDAP bootstrap document")
            mapping: dict[str, list[str]] = {}
            for entry in data.get("services", []):
                tlds = entry[0]
                urls = entry[1]
                for tld in tlds:
                    mapping[tld.lower().lstrip(".")] = urls
            self._bootstrap = mapping
            self._bootstrap_fetched_at = now
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("rdap bootstrap fetch failed: %s", exc)
            self._bootstrap_fetched_at = now  # avoid retry-spam
        return self._bootstrap

    def _find_base_url(self, tld: str) -> str | None:
        candidates = self._bootstrap.get(tld)
        if not candidates:
            return None
        # Prefer https endpoints.
        for url in candidates:
            if url.startswith("https://"):
                return url
        return candidates[0]

    async def lookup(self, domain: str) -> RegistryRecord:
        normalized = normalize_domain(domain)
        registrable = get_registrable_domain(normalized)
        tld = normalized.rsplit(".", 1)[-1]

        await self._get_bootstrap()
        base_url = self._find_base_url(tld)
        if base_url is None:
            raise WHOISProviderError(f"RDAP coverage unavailable for TLD .{tld}")

        target = registrable or normalized
        url = f"{base_url.rstrip('/')}/domain/{target}"
        try:
            parsed_url = httpx.URL(url)
            hostname = parsed_url.host
            addresses = await self._guard.resolve_and_check(hostname) if self._guard and hostname else []
            token = pin_address(hostname, addresses[0]) if addresses else None
            try:
                async with self._client.stream(
                    "GET", url, timeout=self._timeout, follow_redirects=False
                ) as resp:
                    if resp.status_code == 404:
                        raise RegistryNotFoundError(f"No RDAP record for {target}")
                    if resp.status_code >= 400:
                        raise WHOISProviderError("RDAP registry returned an error.")
                    body = bytearray()
                    async for chunk in resp.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > self._max_response_bytes:
                            raise ResourceLimitError("RDAP response exceeds the configured size limit.")
                    import json
                    data = json.loads(bytes(body))
            finally:
                if token is not None:
                    unpin_address(token)
        except httpx.TimeoutException as exc:
            raise WHOISProviderError("RDAP lookup timed out") from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise WHOISProviderError("RDAP lookup failed.") from exc

        return self._parse(data=data, domain=target)

    def _parse(self, data: dict[str, Any], domain: str) -> RegistryRecord:
        record = RegistryRecord(
            domain_name=data.get("ldhName") or data.get("handle") or domain,
            source="rdap",
        )
        record.registrar = self._find_registrar_name(data)
        record.registrar_url = self._find_registrar_url(data)

        statuses = [str(s) for s in data.get("status", [])]
        record.status = statuses

        for event in data.get("events", []):
            kind = event.get("eventAction")
            stamp = self._normalize_timestamp(event.get("eventDate"))
            if not stamp:
                continue
            if kind == "registration":
                record.creation_date = stamp
            elif kind == "expiration":
                record.expiration_date = stamp
            elif kind == "last changed":
                record.updated_date = stamp

        for ns in data.get("nameservers", []):
            ldh = ns.get("ldhName") or ns.get("handle")
            if ldh:
                record.name_servers.append(str(ldh).rstrip(".").lower())

        secure_dns = data.get("secureDNS") or {}
        if secure_dns.get("zoneSigned") or secure_dns.get("delegationSigned"):
            record.dnssec = "signed"
        else:
            record.dnssec = "unsigned" if secure_dns else None

        return record

    @staticmethod
    def _normalize_timestamp(value: Any) -> int | None:
        if isinstance(value, (int, float)) and 0 < value < _TIMESTAMP_MAX:
            return int(value)
        if isinstance(value, str):
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=UTC)
                return int(parsed.timestamp())
            except ValueError:
                return None
        return None

    @staticmethod
    def _find_registrar_name(data: dict[str, Any]) -> str | None:
        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                vcard = entity.get("vcardArray")
                if vcard and len(vcard) == 2:
                    for item in vcard[1]:
                        if len(item) >= 2 and item[0] == "fn":
                            value = item[3]
                            if isinstance(value, str):
                                return value
                public_ids = entity.get("publicIds")
                if public_ids and isinstance(public_ids, list) and public_ids:
                    first = public_ids[0]
                    if isinstance(first, dict):
                        return first.get("value") or first.get("identifier")
        return None

    @staticmethod
    def _find_registrar_url(data: dict[str, Any]) -> str | None:
        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                for link in entity.get("links", []):
                    href = link.get("href")
                    if isinstance(href, str) and href.lower().startswith(("http://", "https://")):
                        return href
                # publicIds only carry identifiers like the IANA registrar ID
                # (a number), which is not a URL - never return it as a URL.
        return None
