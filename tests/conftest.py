"""Shared fixtures for offline, deterministic tests.

Tests never depend on the internet, third-party APIs, WHOIS servers or public
DNS. External providers are replaced with fakes defined in ``tests.fakes`` so
everything here runs offline and deterministically.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from app.core.config import Settings
from app.providers.geoip.base import GeoIPResult
from app.providers.ipintel.base import IPIntelligence
from app.repositories.cache import MemoryCache
from app.repositories.host_lists import (
    DisposableEmailRepository,
    HostListRepository,
    MaliciousHostRepository,
)
from app.services.whois_service import WhoIsService

from .fakes import (
    FakeDNSProvider,
    FakeGeoIPProvider,
    FakeIPIntelligenceProvider,
    FakeRDPAProvider,
    FakeWhoIsProvider,
)


@pytest.fixture
def settings() -> Settings:
    """A minimal settings object with caching and rate limiting disabled."""
    return Settings(
        app_env="test",
        cache_enabled=False,
        rate_limit_enabled=False,
        metrics_enabled=False,
        geoip_provider="none",
        webpage_max_redirects=5,
    )


@pytest.fixture
def cache() -> MemoryCache:
    return MemoryCache()


@pytest.fixture
def fake_dns() -> FakeDNSProvider:
    return FakeDNSProvider()


@pytest.fixture
def fake_geoip() -> FakeGeoIPProvider:
    return FakeGeoIPProvider(
        GeoIPResult(
            country="United States",
            country_code="US",
            region="California",
            city="Mountain View",
            asn="AS15169",
            asn_name="GOOGLE",
            is_datacenter=True,
            is_hosting=True,
        )
    )


@pytest.fixture
def fake_intel() -> FakeIPIntelligenceProvider:
    return FakeIPIntelligenceProvider(
        IPIntelligence(
            is_datacenter=True,
            is_hosting=True,
            is_vpn=False,
            threat_level="low",
        )
    )


@pytest.fixture
def rdap() -> FakeRDPAProvider:
    return FakeRDPAProvider()


@pytest.fixture
def whois() -> FakeWhoIsProvider:
    return FakeWhoIsProvider()


@pytest.fixture
def disposable_repo() -> DisposableEmailRepository:
    return DisposableEmailRepository({"guerrillamail.com", "mailinator.com", "example.com"})
@pytest.fixture
def free_hosts() -> HostListRepository:
    return HostListRepository({"gmail.com", "outlook.com", "yahoo.com"})


@pytest.fixture
def risky_tlds() -> HostListRepository:
    return HostListRepository({"top", "xyz", "click", "zip", "men", "rest"})


@pytest.fixture
def malicious_repo() -> MaliciousHostRepository:
    return MaliciousHostRepository(
        {"evil.example.com", "phish.example.net", "example.com"}
    )


@pytest.fixture
def whois_service(rdap, whois, cache, settings) -> WhoIsService:
    return WhoIsService(rdap, whois, cache, settings, metrics=None)


@pytest.fixture
def http_transport() -> httpx.AsyncClient:
    """An AsyncClient whose transport always returns deterministic HTML."""
    page = (
        "<!DOCTYPE html><html><head>"
        "<title>Example Domain</title>"
        '<meta name="description" content="A test page">'
        '<link rel="icon" href="/favicon.ico"></head>'
        "<body><h1>Hello</h1></body></html>"
    )
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            headers={"Content-Type": "text/html"},
            content=page.encode("utf-8"),
        )
    )
    return httpx.AsyncClient(transport=transport, base_url="https://example.com")


@pytest.fixture
async def async_client_factory() -> AsyncIterator[None]:
    yield
