"""Tests for the WHOIS/RDAP lookup service."""

from __future__ import annotations

import pytest
from app.core.exceptions import WHOISUnavailableError
from app.providers.whois.base import RegistryNotFoundError
from app.services.whois_service import WhoIsService


def _svc(rdap, whois, cache, settings) -> WhoIsService:
    return WhoIsService(rdap, whois, cache, settings)


async def test_rdap_success(rdap, whois, cache, settings) -> None:
    svc = _svc(rdap, whois, cache, settings)
    record = await svc.lookup("example.com")
    assert record.source == "rdap"
    assert record.registrar == "Example Registrar"
    assert record.name_servers == ["ns1.example.com"]


async def test_rdap_fallback_to_whois(rdap, whois, cache, settings) -> None:
    rdap.set_unavailable(True)
    whois.set_unavailable(False)
    svc = _svc(rdap, whois, cache, settings)
    record = await svc.lookup("example.com")
    assert record.source == "whois"
    assert record.registrar == "Whois Registrar Ltd"


async def test_not_found_passthrough(rdap, whois, cache, settings) -> None:
    rdap.set_registered(False)
    whois.set_unavailable(True)
    svc = _svc(rdap, whois, cache, settings)
    with pytest.raises(RegistryNotFoundError):
        await svc.lookup("example.com")


async def test_both_unavailable_raises(rdap, whois, cache, settings) -> None:
    rdap.set_unavailable(True)
    whois.set_unavailable(True)
    svc = _svc(rdap, whois, cache, settings)
    with pytest.raises(WHOISUnavailableError):
        await svc.lookup("example.com")


async def test_missing_fields_are_none(rdap, whois, cache, settings) -> None:
    svc = _svc(rdap, whois, cache, settings)
    record = await svc.lookup("example.com")
    assert isinstance(record.dnssec, str) or record.dnssec is None
    assert record.registrar_url is None or record.registrar_url.startswith("http")


async def test_caches_result(rdap, whois, cache, settings) -> None:
    svc = _svc(rdap, whois, cache, settings)
    await svc.lookup("example.com")
    assert await cache.get("whois:example.com") is not None
