"""Optional MaxMind GeoIP2 provider.

Requires a local MaxMind .mmdb database. The library ``geoip2`` is an optional
dependency: if this provider is selected but the library/database is missing,
the provider raises a configuration error instead of pretending to work.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.providers.geoip.base import GeoIPResult, MaxMindUnavailableError
from app.providers.geoip.none import NullGeoIPProvider


class MaxMindGeoIPProvider(NullGeoIPProvider):
    """Loads MaxMind Country/City/ASN databases on first use.

    The data files (and the ``geoip2`` package) are not bundled with the
    project; configure a database path to enable this provider.
    """

    def __init__(self, db_path: str = "") -> None:
        self._db_path = db_path
        self._reader: Any = None  # lazy

    def _ensure(self) -> None:
        if self._reader is not None:
            return
        try:
            import geoip2.database
        except ImportError as exc:
            raise MaxMindUnavailableError(
                "geoip2 is not installed; choose a different GEOIP_PROVIDER"
            ) from exc
        path = Path(self._db_path)
        if not path.exists():
            raise MaxMindUnavailableError(f"MaxMind database not found: {self._db_path}")
        self._reader = geoip2.database.Reader(str(path))

    async def lookup(self, ip: str) -> GeoIPResult:
        self._ensure()
        # For enterprise deployments this provider's blocking call should be
        # executed via asyncio.to_thread; local file reads are fast.
        import asyncio

        def _block() -> GeoIPResult:
            return self._block_lookup(ip)

        return await asyncio.to_thread(_block)

    def _block_lookup(self, ip: str) -> GeoIPResult:
        if self._reader is None:
            raise MaxMindUnavailableError("MaxMind reader not initialized")
        try:
            city = self._reader.city(ip)
        except Exception:
            return GeoIPResult()
        country = city.country.names.get("en")
        region = city.subdivisions.most_specific.names.get("en") if city.subdivisions else None
        region_code = city.subdivisions.most_specific.iso_code if city.subdivisions else None
        return GeoIPResult(
            country=country,
            country_code=city.country.iso_code,
            region=region,
            region_code=region_code,
            city=city.city.names.get("en") if city.city else None,
            zip=(city.postal.code if city.postal else None),
            lat=float(city.location.latitude if city.location else 0.0) or None,
            lon=float(city.location.longitude if city.location else 0.0) or None,
            timezone=city.location.time_zone if city.location else None,
        )
