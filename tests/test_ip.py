"""Tests for IP lookup service."""

from __future__ import annotations

import pytest
from app.services.ip_service import IPLookupError, IPService


def _svc(fake_geoip, fake_intel, cache, settings) -> IPService:
    return IPService(fake_geoip, fake_intel, cache, settings)


async def test_ipv4(fake_geoip, fake_intel, cache, settings) -> None:
    result = await _svc(fake_geoip, fake_intel, cache, settings).lookup("8.8.8.8")
    assert result["is_valid"] is True
    assert result["ip_version"] == 4


async def test_ipv6(fake_geoip, fake_intel, cache, settings) -> None:
    result = await _svc(fake_geoip, fake_intel, cache, settings).lookup("2606:4700:4700::1111")
    assert result["is_valid"] is True
    assert result["ip_version"] == 6


async def test_private_ip_never_sent_to_provider(fake_geoip, fake_intel, cache, settings) -> None:
    svc = _svc(fake_geoip, fake_intel, cache, settings)
    result = await svc.lookup("10.0.0.1")
    assert result["is_private"] is True
    assert result["country"] is None
    assert fake_geoip.calls == []


async def test_loopback(fake_geoip, fake_intel, cache, settings) -> None:
    result = await _svc(fake_geoip, fake_intel, cache, settings).lookup("127.0.0.1")
    assert result["is_loopback"] is True


async def test_invalid_ip_raises(fake_geoip, fake_intel, cache, settings) -> None:
    with pytest.raises(IPLookupError):
        await _svc(fake_geoip, fake_intel, cache, settings).lookup("not-an-ip")


async def test_reserved(fake_geoip, fake_intel, cache, settings) -> None:
    result = await _svc(fake_geoip, fake_intel, cache, settings).lookup("192.0.2.1")
    assert result["is_valid"] is True
    # TEST-NET-1 is documentation/reserved; provider should not be contacted.
    assert fake_geoip.calls == []


async def test_public_uses_geoip(fake_geoip, fake_intel, cache, settings) -> None:
    svc = _svc(fake_geoip, fake_intel, cache, settings)
    result = await svc.lookup("8.8.8.8")
    assert result["country_code"] == "US"
    assert fake_geoip.calls == ["8.8.8.8"]


async def test_intelligence_falls_back_to_geo_fields(cache, settings) -> None:
    from app.providers.geoip.base import GeoIPResult
    from app.providers.ipintel.base import IPIntelligence
    from app.services.ip_service import IPService

    from tests.fakes import FakeGeoIPProvider, FakeIPIntelligenceProvider

    geo = FakeGeoIPProvider(
        GeoIPResult(
            country="United States",
            country_code="US",
            is_vpn=True,
            is_icloud_relay=True,
            is_abuser=True,
        )
    )
    intel = FakeIPIntelligenceProvider(IPIntelligence())
    result = await IPService(geo, intel, cache, settings).lookup("8.8.8.8")

    assert result["is_vpn"] is True
    assert result["is_icloud_relay"] is True
    assert result["is_abuser"] is True
