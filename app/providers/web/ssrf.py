"""SSRF protection for outbound fetchers.

Mitigations:

* Validate the hostname format up front.
* Resolve the hostname (A/AAAA) *before* connecting and reject any address in
  the private/loopback/link-local/metadata ranges.
* Re-validate every redirect destination.
* Pin validated DNS answers at the TCP transport boundary.

The resolution strategy uses the async DNS provider so it honours configured
nameservers and timeouts.
"""

from __future__ import annotations

import ipaddress
import logging
from contextvars import ContextVar, Token
from typing import Any

import httpcore
import httpx

from app.core.exceptions import ResolutionBlockedError
from app.providers.dns.base import DNSProvider

logger = logging.getLogger(__name__)


_PINNED_ADDRESSES: ContextVar[dict[str, str]] = ContextVar(
    "ssrf_pinned_addresses", default={}
)


class PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Network backend that pins a previously SSRF-checked hostname to one IP.

    httpx/httpcore still sees the original hostname for HTTP Host/SNI semantics,
    but the TCP connection is made to the exact address validated by SSRFGuard.
    """

    def __init__(self) -> None:
        self._fallback = httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> Any:
        pinned = _PINNED_ADDRESSES.get().get(host.lower(), host)
        return await self._fallback.connect_tcp(
            pinned,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )


def pin_address(hostname: str, address: str) -> Token[dict[str, str]]:
    current = dict(_PINNED_ADDRESSES.get())
    current[hostname.lower()] = address
    return _PINNED_ADDRESSES.set(current)


def unpin_address(token: Token[dict[str, str]]) -> None:
    _PINNED_ADDRESSES.reset(token)


class SSRFHttpTransport(httpx.AsyncHTTPTransport):
    """httpx transport with DNS pinning for SSRF-guarded requests."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        # AsyncHTTPTransport intentionally exposes no public network-backend
        # injection point. The underlying httpcore pool is stable across the
        # supported httpx 0.27-0.x range used by this project.
        self._pool._network_backend = PinnedNetworkBackend()  # type: ignore[attr-defined]

class SSRFGuard:
    def __init__(self, resolver: DNSProvider) -> None:
        self._resolver = resolver

    async def resolve_and_check(self, hostname: str) -> list[str]:
        """Resolve a hostname and return its public addresses.

        Raises ResolutionBlockedError when the hostname cannot be resolved or
        resolves to a forbidden (private/loopback/metadata) address.
        """
        hostname = hostname.strip().rstrip(".").lower()
        if not hostname or "%" in hostname or any(ch.isspace() for ch in hostname):
            raise ResolutionBlockedError("Invalid hostname.")
        # Canonicalize internationalized hostnames before DNS lookup.
        try:
            literal = ipaddress.ip_address(hostname.strip("[]"))
        except ValueError:
            literal = None
        if literal is not None:
            if self._is_blocked(literal):
                raise ResolutionBlockedError(f"Blocked address: {hostname}")
            return [str(literal)]

        try:
            import idna
            hostname = idna.encode(hostname, uts46=True).decode("ascii").lower()
        except Exception as exc:
            raise ResolutionBlockedError("Invalid hostname.") from exc

        addrs = await self._resolver.resolve_a_aaaa(hostname)
        if not addrs:
            raise ResolutionBlockedError(f"Could not resolve hostname: {hostname}")

        public: list[str] = []
        for addr in addrs:
            try:
                ip = ipaddress.ip_address(addr)
            except ValueError as exc:
                raise ResolutionBlockedError(f"Address {addr!r} is not a valid IP") from exc
            if self._is_blocked(ip):
                raise ResolutionBlockedError(
                    f"Hostname {hostname} resolves to a disallowed address: {addr}"
                )
            public.append(str(ip))
        return public

    @staticmethod
    def _is_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        if ip.is_loopback or ip.is_private or ip.is_link_local:
            return True
        if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return True
        # Global reachability is the final guardrail for both address families.
        if not ip.is_global:
            return True
        if ip in ipaddress.ip_network("100.64.0.0/10"):  # RFC6598 CGNAT
            return True
        if ip in ipaddress.ip_network("169.254.169.254/32"):  # cloud metadata
            return True
        if ip in ipaddress.ip_network("fd00:ec2::/48"):
            return True
        return ip.exploded.startswith("fe80:")


    def validate_ip_target(self, ip_str: str) -> str:
        """Validate a literal IP formed from a URL host (no resolution)."""
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError as exc:
            raise ResolutionBlockedError(f"Invalid IP target: {ip_str}") from exc
        if self._is_blocked(ip):
            raise ResolutionBlockedError(f"Blocked address: {ip_str}")
        return str(ip)
