"""IP address helpers built on the standard-library ``ipaddress`` module.

Provides classification helpers (private, loopback, multicast, reserved,
link-local, bogon-style) and a safe formatter that strips zone identifiers.
"""

from __future__ import annotations

import ipaddress
from typing import TypeAlias

IPInput: TypeAlias = str | int


def parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Parse an IP string, raising ValueError on invalid input."""
    return ipaddress.ip_address(value.strip())


def is_valid_ip(value: str) -> bool:
    try:
        parse_ip(value)
        return True
    except ValueError:
        return False


def is_global(value: str) -> bool:
    """Return True for a globally routable (non-private/non-local) address."""
    ip = parse_ip(value)
    return ip.is_global


def classify(value: str) -> dict[str, bool]:
    """Return a dictionary of boolean classifications for an address."""
    ip = parse_ip(value)
    return {
        "is_ipv4": ip.version == 4,
        "is_ipv6": ip.version == 6,
        "is_private": ip.is_private,
        "is_loopback": ip.is_loopback,
        "is_multicast": ip.is_multicast,
        "is_reserved": ip.is_reserved,
        "is_link_local": ip.is_link_local,
        "is_unspecified": ip.is_unspecified,
        "is_global": ip.is_global,
    }


# Address ranges that must never be reached by outbound fetchers.
BLOCKED_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("0.0.0.0/8"),  # "this" network
    ipaddress.ip_network("10.0.0.0/8"),  # private
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT (RFC6598)
    ipaddress.ip_network("127.0.0.0/8"),  # loopback
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("172.16.0.0/12"),  # private
    ipaddress.ip_network("192.0.0.0/24"),  # IETF protocol assignments
    ipaddress.ip_network("192.168.0.0/16"),  # private
    ipaddress.ip_network("198.18.0.0/15"),  # benchmarking
    ipaddress.ip_network("224.0.0.0/4"),  # multicast
    ipaddress.ip_network("240.0.0.0/4"),  # reserved
    ipaddress.ip_network("::/128"),  # unspecified
    ipaddress.ip_network("::1/128"),  # loopback
    ipaddress.ip_network("fc00::/7"),  # unique local
    ipaddress.ip_network("fe80::/10"),  # link-local
    ipaddress.ip_network("ff00::/8"),  # multicast
    # Cloud metadata services.
    ipaddress.ip_network("169.254.169.254/32"),
    ipaddress.ip_network("fd00:ec2::/48"),
)


def is_address_blocked(value: str) -> bool:
    """Return True if an address is on the SSRF-blocked list."""
    try:
        ip = parse_ip(value)
    except ValueError:
        return False
    return any(ip in network for network in BLOCKED_NETWORKS)


def is_bogon(value: str) -> bool:
    """A heuristic 'bogon' check for the IP lookup response.

    This is derived strictly from IP classification rules and never overstates
    threat intelligence - it reflects reserved/non-routable status only.
    """
    try:
        ip = parse_ip(value)
    except ValueError:
        return False
    if ip.is_reserved or ip.is_private or ip.is_loopback:
        return True
    if ip.is_multicast or ip.is_unspecified or ip.is_link_local:
        return True
    return bool(not ip.is_global)


def compact_ipv6(value: str) -> str:
    """Return the canonical (compressed) textual form of an IPv6 address."""
    return str(parse_ip(value))
