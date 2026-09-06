"""Tests for the MX lookup service."""

from __future__ import annotations

from app.services.mx_service import MXService


async def test_domain_with_mx(fake_dns, cache, settings) -> None:
    svc = MXService(fake_dns, cache, settings)
    domain, hosts = await svc.lookup("gmail.com")
    assert domain == "gmail.com"
    assert hosts
    assert all(h.hostname and h.priority is not None for h in hosts)


async def test_domain_without_mx(fake_dns, cache, settings) -> None:
    svc = MXService(fake_dns, cache, settings)
    _, hosts = await svc.lookup("nomx.test")
    assert hosts == []


async def test_normalizes_domain(fake_dns, cache, settings) -> None:
    svc = MXService(fake_dns, cache, settings)
    domain, hosts = await svc.lookup("GMAIL.COM.")
    assert domain == "gmail.com"
    assert len(hosts) == 1


async def test_caches_result(fake_dns, cache, settings) -> None:
    svc = MXService(fake_dns, cache, settings)
    await svc.lookup("gmail.com")
    assert await cache.get("mx:gmail.com") is not None
