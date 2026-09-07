"""Production-hardening regression tests."""
from __future__ import annotations

import asyncio
import ipaddress

import pytest
from app.core.config import Settings
from app.core.exceptions import ResolutionBlockedError, ValidationError
from app.core.ratelimit import MemoryRateLimiter
from app.providers.web.ssrf import SSRFGuard


class Resolver:
    def __init__(self, addresses: list[str]) -> None:
        self.addresses = addresses

    async def resolve_a_aaaa(self, host: str) -> list[str]:
        del host
        return self.addresses


@pytest.mark.asyncio
async def test_rate_limit_enforces_and_resets() -> None:
    limiter = MemoryRateLimiter()
    assert (await limiter.check("k", 2, 1)).allowed
    assert (await limiter.check("k", 2, 1)).allowed
    blocked = await limiter.check("k", 2, 1)
    assert not blocked.allowed
    assert blocked.remaining == 0
    await asyncio.sleep(1.05)
    assert (await limiter.check("k", 2, 1)).allowed


@pytest.mark.asyncio
async def test_rate_limit_concurrent_requests_are_atomic() -> None:
    limiter = MemoryRateLimiter()
    decisions = await asyncio.gather(
        *(limiter.check("same", 3, 60) for _ in range(20))
    )
    assert sum(item.allowed for item in decisions) == 3


@pytest.mark.asyncio
async def test_rate_limit_state_is_bounded() -> None:
    limiter = MemoryRateLimiter(max_keys=10)
    for i in range(100):
        await limiter.check(f"k-{i}", 1, 60)
    assert len(limiter._counts) <= 10


@pytest.mark.asyncio
async def test_ssrf_blocks_private_and_special_ranges() -> None:
    blocked = [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "::1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
    ]
    for address in blocked:
        guard = SSRFGuard(Resolver([address]))
        with pytest.raises(ResolutionBlockedError):
            await guard.resolve_and_check("example.com")


@pytest.mark.asyncio
async def test_ssrf_rejects_mixed_public_private_dns_results() -> None:
    guard = SSRFGuard(Resolver(["8.8.8.8", "10.0.0.1"]))
    with pytest.raises(ResolutionBlockedError):
        await guard.resolve_and_check("rebind.example")


@pytest.mark.asyncio
async def test_ssrf_allows_global_address() -> None:
    guard = SSRFGuard(Resolver(["8.8.8.8"]))
    assert await guard.resolve_and_check("example.com") == ["8.8.8.8"]


def test_ssrf_network_classification_matches_ipaddress() -> None:
    assert ipaddress.ip_address("127.0.0.1").is_loopback
    assert ipaddress.ip_address("::1").is_loopback


def test_settings_include_hardening_defaults() -> None:
    settings = Settings(app_env="test")
    assert settings.max_request_body_bytes > 0
    assert settings.max_json_depth > 0
    assert settings.rate_limit_network_requests < settings.rate_limit_requests
    assert settings.cache_max_entries > 0


def test_xml_entity_expansion_is_rejected() -> None:
    from app.core.exceptions import AwesomeAPIError
    from app.services.data_tools_service import DataToolsService

    xml = """<!DOCTYPE lolz [
      <!ENTITY lol "lol">
      <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
    ]><lolz>&lol1;</lolz>"""
    with pytest.raises(AwesomeAPIError):
        DataToolsService().xml_convert("xml_to_json", xml, "")


def test_yaml_recursive_alias_is_rejected() -> None:
    from app.services.data_tools_service import DataToolsService

    yaml_text = "a: &a [*a]"
    with pytest.raises(ValidationError):
        DataToolsService().yaml_convert("yaml_to_json", yaml_text)


def test_sql_tool_is_local_only(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.services.dev_tools_service import DevToolsService

    def fail(*args: object, **kwargs: object) -> None:
        raise AssertionError("network/database execution attempted")

    monkeypatch.setattr("socket.create_connection", fail, raising=False)
    result = DevToolsService.sql_validate("SELECT 1")
    assert "valid" in result
    assert "errors" in result


def test_openapi_inventory_and_examples() -> None:
    from app.main import app

    spec = app.openapi()
    operations = sum(
        1
        for item in spec["paths"].values()
        for method in item
        if method.lower() in {"get", "post", "put", "patch", "delete", "head", "options"}
    )
    assert operations == 72
    assert "/api/v1/jwt/inspect" in spec["paths"]
    assert "/health" in spec["paths"]
    for item in spec["paths"].values():
        for method, operation in item.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete", "head", "options"}:
                continue
            if "requestBody" in operation:
                media = next(iter(operation["requestBody"]["content"].values()))
                assert "examples" in media


@pytest.mark.asyncio
async def test_memory_cache_hit_expiration_and_key_isolation() -> None:
    from app.repositories.cache import MemoryCache

    cache = MemoryCache(max_entries=10)
    calls = 0

    async def factory() -> str:
        nonlocal calls
        calls += 1
        return "value"

    assert await cache.get_or_set("a:1", 1, factory) == "value"
    assert await cache.get_or_set("a:1", 1, factory) == "value"
    assert await cache.get_or_set("a:2", 1, factory) == "value"
    assert calls == 2
    await asyncio.sleep(1.05)
    assert await cache.get("a:1") is None


@pytest.mark.asyncio
async def test_cache_concurrent_get_or_set_coalesces() -> None:
    from app.repositories.cache import MemoryCache

    cache = MemoryCache()
    calls = 0

    async def factory() -> str:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.01)
        return "ok"

    results = await asyncio.gather(*(cache.get_or_set("same", 10, factory) for _ in range(20)))
    assert results == ["ok"] * 20
    assert calls == 1


def test_request_id_is_validated_and_returned() -> None:
    from app.core.middleware import RequestContextMiddleware
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()
    app.add_middleware(RequestContextMiddleware, settings=Settings(app_env="test"))

    @app.get("/ping")
    def ping() -> dict[str, bool]:
        return {"ok": True}

    client = TestClient(app)
    response = client.get("/ping", headers={"X-Request-ID": "client.request-123"})
    assert response.headers["X-Request-ID"] == "client.request-123"
    response = client.get("/ping", headers={"X-Request-ID": "bad id with spaces"})
    assert response.headers["X-Request-ID"]
    assert len(response.headers["X-Request-ID"]) == 32
