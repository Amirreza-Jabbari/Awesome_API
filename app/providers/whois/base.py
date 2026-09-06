"""WHOIS/RDAP provider abstractions and shared data model."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from app.core.exceptions import WHOISUnavailableError


@dataclass(slots=True)
class RegistryRecord:
    """Unified registration record used by services regardless of provider."""

    domain_name: str | None = None
    registrar: str | None = None
    registrar_url: str | None = None
    whois_server: str | None = None
    updated_date: int | None = None
    creation_date: int | None = None
    expiration_date: int | None = None
    name_servers: list[str] = field(default_factory=list)
    dnssec: str | None = None
    status: list[str] = field(default_factory=list)
    source: str | None = None


class WhoIsProvider(Protocol):
    async def lookup(self, domain: str) -> RegistryRecord: ...


class WHOISProviderError(WHOISUnavailableError):
    """Raised by providers when the registry does not supply usable data."""


class RegistryNotFoundError(WHOISProviderError):
    """Raised when the registry explicitly reports that the domain is not
    registered (e.g. RDAP 404 or a 'No match' WHOIS response)."""
