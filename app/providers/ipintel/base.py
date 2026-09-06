"""IP intelligence provider abstraction.

Threat signals (VPN, Tor, hosting, datacenter, iCloud relay, abuse reputation,
threat level) cannot be reliably derived from IP classification alone. The
service layer therefore depends on this protocol; a null provider returns
``None`` for every uncertain signal so the API never fabricates threat
intelligence.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(slots=True)
class IPIntelligence:
    is_datacenter: bool | None = None
    is_hosting: bool | None = None
    is_tor: bool | None = None
    is_vpn: bool | None = None
    is_icloud_relay: bool | None = None
    is_abuser: bool | None = None
    threat_level: str | None = None
    notes: str | None = None


class IPIntelligenceProvider(Protocol):
    async def lookup(self, ip: str) -> IPIntelligence: ...
