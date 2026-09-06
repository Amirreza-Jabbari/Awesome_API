"""Tests for the SSRF guard."""

from __future__ import annotations

import ipaddress

import pytest
from app.core.exceptions import ResolutionBlockedError
from app.providers.web.ssrf import SSRFGuard


def _guard(fake_dns, addr_table: dict[str, list[str]]) -> SSRFGuard:
    fake_dns.addr_table.update(addr_table)
    return SSRFGuard(fake_dns)


async def test_blocks_private_ip(fake_dns) -> None:
    guard = _guard(fake_dns, {"private.test": ["10.0.0.1"]})
    with pytest.raises(ResolutionBlockedError):
        await guard.resolve_and_check("private.test")


async def test_blocks_loopback(fake_dns) -> None:
    guard = _guard(fake_dns, {"loopback.test": ["127.0.0.1"]})
    with pytest.raises(ResolutionBlockedError):
        await guard.resolve_and_check("loopback.test")


async def test_blocks_cloud_metadata(fake_dns) -> None:
    guard = _guard(fake_dns, {"metadata.test": ["169.254.169.254"]})
    with pytest.raises(ResolutionBlockedError):
        await guard.resolve_and_check("metadata.test")


async def test_blocks_link_local(fake_dns) -> None:
    guard = _guard(fake_dns, {"linklocal.test": ["169.254.1.1"]})
    with pytest.raises(ResolutionBlockedError):
        await guard.resolve_and_check("linklocal.test")


async def test_blocks_cgnat(fake_dns) -> None:
    guard = _guard(fake_dns, {"cgnat.test": ["100.64.0.1"]})
    with pytest.raises(ResolutionBlockedError):
        await guard.resolve_and_check("cgnat.test")


async def test_allows_public_ip(fake_dns) -> None:
    guard = SSRFGuard(fake_dns)
    result = await guard.resolve_and_check("example.com")
    assert result == ["93.184.216.34"]


async def test_unresolvable_raises(fake_dns) -> None:
    guard = SSRFGuard(fake_dns)
    with pytest.raises(ResolutionBlockedError):
        await guard.resolve_and_check("does-not-exist.invalid")


def test_static_block_checks() -> None:
    assert SSRFGuard._is_blocked(ipaddress.ip_address("127.0.0.1")) is True
    assert SSRFGuard._is_blocked(ipaddress.ip_address("10.1.2.3")) is True
    assert SSRFGuard._is_blocked(ipaddress.ip_address("169.254.169.254")) is True
    assert SSRFGuard._is_blocked(ipaddress.ip_address("100.64.0.1")) is True
    assert SSRFGuard._is_blocked(ipaddress.ip_address("8.8.8.8")) is False
    assert SSRFGuard._is_blocked(ipaddress.ip_address("::1")) is True
