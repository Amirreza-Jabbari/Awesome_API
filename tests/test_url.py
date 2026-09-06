"""Tests for the URL lookup service."""

from __future__ import annotations

import pytest
from app.services.url_service import URLService
from app.utils.ip import is_address_blocked


def _svc(fake_dns, fake_geoip, cache, settings) -> URLService:
    return URLService(fake_dns, fake_geoip, cache, settings)


async def test_http_url(fake_dns, fake_geoip, cache, settings) -> None:
    result = await _svc(fake_dns, fake_geoip, cache, settings).lookup("http://example.com")
    assert result["is_valid"] is True
    assert result["ip"] == "93.184.216.34"


async def test_https_url(fake_dns, fake_geoip, cache, settings) -> None:
    result = await _svc(fake_dns, fake_geoip, cache, settings).lookup("https://example.com")
    assert result["is_valid"] is True


async def test_schemeless_defaults_to_https(fake_dns, fake_geoip, cache, settings) -> None:
    result = await _svc(fake_dns, fake_geoip, cache, settings).lookup("example.com")
    assert result["url"].startswith("https://")


async def test_path_and_query_preserved(fake_dns, fake_geoip, cache, settings) -> None:
    result = await _svc(fake_dns, fake_geoip, cache, settings).lookup("http://example.com/path?a=1")
    assert "/path?a=1" in result["url"]


async def test_invalid_url(fake_dns, fake_geoip, cache, settings) -> None:
    from app.core.exceptions import InvalidURLError

    with pytest.raises(InvalidURLError):
        await _svc(fake_dns, fake_geoip, cache, settings).lookup("://garbage")


async def test_localhost_rejected(fake_dns, fake_geoip, cache, settings) -> None:
    from app.core.exceptions import InvalidURLError

    with pytest.raises(InvalidURLError):
        await _svc(fake_dns, fake_geoip, cache, settings).lookup("http://localhost")


async def test_unresolvable_host_raises_ssrf(fake_dns, fake_geoip, cache, settings) -> None:
    from app.core.exceptions import SSRFBlockedError

    with pytest.raises(SSRFBlockedError):
        await _svc(fake_dns, fake_geoip, cache, settings).lookup("http://does-not-exist.invalid")


async def test_ip_classification_blocks_private(fake_dns, fake_geoip, cache, settings) -> None:
    # SSRF guard for the webpage fetcher relies on this classification.
    assert is_address_blocked("127.0.0.1") is True
    assert is_address_blocked("10.0.0.1") is True
    assert is_address_blocked("169.254.169.254") is True
    assert is_address_blocked("8.8.8.8") is False


async def test_ipv6_literal_url(fake_dns, fake_geoip, cache, settings) -> None:
    result = await _svc(fake_dns, fake_geoip, cache, settings).lookup(
        "http://[2606:4700:4700::1111]"
    )
    assert result["ip"] == "2606:4700:4700::1111"
