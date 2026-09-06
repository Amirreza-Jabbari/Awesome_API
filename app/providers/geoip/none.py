"""Null GeoIP provider.

Returns no intelligence. Used when no provider is configured so the API still
works and returns only locally-established fields (validation, bogon status,
privacy classification). Never fabricates data.
"""

from __future__ import annotations

from app.providers.geoip.base import GeoIPResult


class NullGeoIPProvider:
    async def lookup(self, ip: str) -> GeoIPResult:
        return GeoIPResult()
