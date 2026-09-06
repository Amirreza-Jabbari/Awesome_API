"""Tests for the DNS lookup service."""

from __future__ import annotations

from app.providers.dns.models import DNSLookupResult
from app.services.dns_service import DNSService


async def test_lookup_default_types(fake_dns, cache, settings) -> None:
    svc = DNSService(fake_dns, cache, settings)
    result = await svc.lookup("example.com")
    assert isinstance(result, DNSLookupResult)
    types = {r.record_type for r in result.records}
    assert "A" in types
    assert "MX" in types


async def test_lookup_specific_types(fake_dns, cache, settings) -> None:
    svc = DNSService(fake_dns, cache, settings)
    result = await svc.lookup("example.com", ["A", "AAAA"])
    types = {r.record_type for r in result.records}
    assert types == {"A", "AAAA"}


async def test_lookup_normalizes_domain(fake_dns, cache, settings) -> None:
    svc = DNSService(fake_dns, cache, settings)
    result = await svc.lookup("EXAMPLE.COM.")
    assert result.domain == "example.com"


async def test_lookup_uses_cache(fake_dns, cache, settings) -> None:
    svc = DNSService(fake_dns, cache, settings)
    first = await svc.lookup("example.com")
    second = await svc.lookup("example.com")
    assert len(first.records) == len(second.records)
    assert await cache.get("dns:example.com:A,AAAA,MX,NS,SOA,TXT,CNAME") is not None


async def test_record_types_none_means_all(fake_dns, cache, settings) -> None:
    svc = DNSService(fake_dns, cache, settings)
    result = await svc.lookup("example.com", None)
    assert {r.record_type for r in result.records} == {
        "A", "AAAA", "MX", "NS", "SOA", "TXT", "CNAME"
    }
