"""WHOIS provider built on the ``python-whois`` library.

The library performs blocking network I/O, so all calls are run in the
asyncio threadpool via ``asyncio.to_thread``. Note that ``python-whois``
internally prefers RDAP when the registry supports it; it is used here only
as a fallback when the dedicated RDAP provider is unavailable.
"""

from __future__ import annotations

import asyncio
import datetime
import logging
from typing import Any

import whois
import whois.parser

from app.core.config import Settings
from app.providers.whois.base import (
    RegistryNotFoundError,
    RegistryRecord,
    WHOISProviderError,
)

# Markers used by registries to signal an unregistered domain.
_NOT_FOUND_MARKERS = (
    "no match for",
    "not found",
    "not registered",
    "no entries found",
    "no data found",
    "nothing found",
)

logger = logging.getLogger(__name__)


# Some registries return attributes as lists; some as single values.
def _first(value: Any) -> Any:
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _to_timestamp(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, datetime.datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=datetime.UTC)
        return int(value.timestamp())
    if isinstance(value, str):
        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d",
        ):
            try:
                parsed = datetime.datetime.strptime(value, fmt)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=datetime.UTC)
                return int(parsed.timestamp())
            except ValueError:
                continue
    return None


def _looks_not_found(text: str, domain: str) -> bool:
    lowered = text.lower()
    lowered_domain = domain.lower().rstrip(".")
    if lowered_domain in lowered and any(m in lowered for m in _NOT_FOUND_MARKERS):
        return True
    # Some registries only print a bare marker without echoing the domain.
    return any(m in lowered for m in _NOT_FOUND_MARKERS) and "registrant" not in lowered


def _clean_ns(value: Any) -> list[str]:
    seen: list[str] = []
    for item in _as_list(value):
        name = str(item).strip().rstrip(".").lower()
        if name and name not in seen:
            seen.append(name)
    return seen


def _urlish(value: Any) -> str | None:
    """Return the value only when it looks like a URL; otherwise None."""
    text = str(value).strip() if value else ""
    if text.lower().startswith(("http://", "https://")) and len(text) > 8:
        return text
    return None


class PythonWhoisProvider:
    """WHOIS provider wrapping python-whois in a threadpool."""

    def __init__(self, settings: Settings) -> None:
        self._timeout = settings.whois_timeout

    async def lookup(self, domain: str) -> RegistryRecord:
        def _blocking() -> Any:
            # python-whois does its own DNS and socket I/O without a public
            # timeout parameter; asyncio.to_thread keeps the event loop free.
            return whois.whois(domain)

        try:
            result = await asyncio.to_thread(_blocking)
        except (whois.parser.PywhoisError, OSError, TimeoutError) as exc:
            logger.info("whois failed for %s: %s", domain, exc)
            raise WHOISProviderError(f"WHOIS lookup failed for {domain}") from exc

        if not result or (getattr(result, "text", None) is None and not isinstance(result, dict)):
            raise WHOISProviderError(f"WHOIS returned no data for {domain}")

        # Detect explicit 'not registered' signals so the domain can be treated
        # as available rather than merely unavailable.
        raw_text = ""
        if isinstance(result, dict):
            raw_text = str(result.get("text") or "")
        else:
            raw_text = str(getattr(result, "text", "") or "")
        if _looks_not_found(raw_text, domain):
            raise RegistryNotFoundError(f"No WHOIS record for {domain}")

        record = RegistryRecord(source="whois")
        if isinstance(result, dict):
            record.domain_name = str(_first(result.get("domain_name")) or "").lower()
            record.registrar = str(_first(result.get("registrar")) or None) or None
            record.registrar_url = _urlish(_first(result.get("registrar_url")))
            record.whois_server = str(_first(result.get("whois_server")) or None) or None
            record.creation_date = _to_timestamp(_first(result.get("creation_date")))
            record.updated_date = _to_timestamp(_first(result.get("updated_date")))
            record.expiration_date = _to_timestamp(_first(result.get("expiration_date")))
            record.name_servers = _clean_ns(result.get("name_servers"))
            record.status = [str(s) for s in _as_list(result.get("status"))]
            dnssec = str(_first(result.get("dnssec")) or "")
            record.dnssec = dnssec or None
            return record

        record.domain_name = str(_first(result.domain_name) or domain).lower()
        record.registrar = str(_first(result.registrar)) if _first(result.registrar) else None
        record.registrar_url = _urlish(_first(result.registrar_url))
        record.whois_server = (
            str(_first(result.whois_server)) if _first(result.whois_server) else None
        )
        record.creation_date = _to_timestamp(_first(result.creation_date))
        record.updated_date = _to_timestamp(_first(result.updated_date))
        record.expiration_date = _to_timestamp(_first(result.expiration_date))
        record.name_servers = _clean_ns(result.name_servers)
        record.status = [str(s) for s in _as_list(result.status)]
        dnssec = str(_first(result.dnssec) or "")
        record.dnssec = dnssec or None
        return record
