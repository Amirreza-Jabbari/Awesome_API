"""DNS provider abstraction.

Application services depend on ``DNSProvider`` rather than a concrete DNS
implementation. This allows the resolver implementation to be replaced
without changing service or route code.
"""

from __future__ import annotations

from typing import Protocol

from app.providers.dns.models import DNSLookupResult, DNSQuery, MXData


class DNSProvider(Protocol):
    """Protocol implemented by DNS provider backends."""

    async def lookup(self, query: DNSQuery) -> DNSLookupResult:
        """Resolve the requested DNS record types for a domain."""
        ...

    async def lookup_mx(self, domain: str) -> DNSLookupResult:
        """Resolve MX records for a domain."""
        ...

    async def resolve_a(self, domain: str) -> list[str]:
        """Resolve A records for a domain."""
        ...

    async def resolve_a_aaaa(self, host: str) -> list[str]:
        """Resolve both A and AAAA records for a host."""
        ...

    async def get_mx_hosts(self, domain: str) -> list[MXData]:
        """Return normalized MX records sorted by priority."""
        ...
