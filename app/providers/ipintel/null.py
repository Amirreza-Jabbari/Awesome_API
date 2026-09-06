"""Null IP-intelligence provider.

Returns no threat signals. Extend this model with real sources (e.g. abuse.ch,
Shodan, commercial feeds) behind the same interface. Never fabricates data.
"""

from __future__ import annotations

from app.providers.ipintel.base import IPIntelligence


class NullIPIntelligenceProvider:
    async def lookup(self, ip: str) -> IPIntelligence:
        return IPIntelligence()
