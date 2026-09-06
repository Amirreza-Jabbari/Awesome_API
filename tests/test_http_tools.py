"""HTTP-tools service tests using deterministic in-memory transports (offline)."""

from __future__ import annotations

import httpx
import pytest
from app.core.config import Settings
from app.core.exceptions import ValidationError
from app.providers.web.ssrf import SSRFGuard
from app.services.http_tools_service import HTTPToolsService

from .fakes import FakeDNSProvider


@pytest.fixture
def service() -> HTTPToolsService:
    settings = Settings(
        app_env="test",
        cache_enabled=False,
        rate_limit_enabled=False,
        metrics_enabled=False,
        geoip_provider="none",
    )
    dns = FakeDNSProvider()
    transport = httpx.MockTransport(
        lambda req: httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            content=b'{"ok": true}',
        )
    )
    client = httpx.AsyncClient(transport=transport, base_url="https://example.com")
    return HTTPToolsService(client, SSRFGuard(dns), settings)


async def test_execute_success(service) -> None:
    result = await service.execute(
        "GET", "https://example.com/data", {}, [], None, "text",
        "none", None, None, None, 5.0,
    )
    assert result["mode"] == "execute"
    assert result["status_code"] == 200
    assert result["is_json"] is True
    assert result["error"] is None
    assert result["ssrf_checked"] is True


async def test_execute_ssrf_blocked(service) -> None:
    result = await service.execute(
        "GET", "http://127.0.0.1:8080/", {}, [], None, "text",
        "none", None, None, None, 5.0,
    )
    assert result["mode"] == "execute"
    assert result["status_code"] is None
    assert result["error"] is not None


async def test_inspect_success(service) -> None:
    result = await service.inspect(
        "https://example.com/", "GET", {}, None, False, 5, 2048, 5.0,
    )
    assert result["valid"] is True
    assert result["status_code"] == 200
    assert result["is_json"] is True
    assert result["content_type"] == "application/json"


async def test_inspect_ssrf_blocked(service) -> None:
    result = await service.inspect(
        "http://127.0.0.1:8080/", "GET", {}, None, False, 5, 2048, 5.0,
    )
    assert result["valid"] is False
    assert result["error"] is not None


def test_build_request_basic(service: HTTPToolsService) -> None:
    result = service.build_request(
        "POST", "https://example.com/api", {"X-Token": "abc"},
        [{"name": "q", "value": "1 2"}], '{"x": 1}', "text", "none",
        None, None, None,
    )
    assert result["mode"] == "build"
    assert result["method"] == "POST"
    assert result["ssrf_checked"] is False
    assert result["raw_query"] == "q=1+2"
    assert result["headers"]["X-Token"] == "abc"
    assert result["curl"].startswith("curl")


def test_build_request_json_content_type(service: HTTPToolsService) -> None:
    result = service.build_request(
        "POST", "https://example.com/api", {}, [], '{"a":1}', "json", "none",
        None, None, None,
    )
    assert result["content_type"] == "application/json; charset=utf-8"
    assert result["body_length"] > 0


def test_build_request_basic_auth(service: HTTPToolsService) -> None:
    result = service.build_request(
        "GET", "https://example.com/api", {}, [], None, "text", "basic",
        "user", "pass", None,
    )
    assert result["headers"]["Authorization"].startswith("Basic ")


def test_build_request_bearer_auth(service: HTTPToolsService) -> None:
    result = service.build_request(
        "GET", "https://example.com/api", {}, [], None, "text", "bearer",
        None, None, "tok123",
    )
    assert result["headers"]["Authorization"] == "Bearer tok123"


def test_build_request_rejects_userinfo_urls(service: HTTPToolsService) -> None:
    with pytest.raises(ValidationError):
        service.build_request(
            "GET", "https://user:pass@example.com/", {}, [], None, "text",
            "none", None, None, None,
        )


def test_build_request_invalid_json_body(service: HTTPToolsService) -> None:
    with pytest.raises(ValidationError):
        service.build_request(
            "POST", "https://example.com/api", {}, [], "not json", "json",
            "none", None, None, None,
        )


def test_generate_curl_flags(service: HTTPToolsService) -> None:
    result = service.generate_curl(
        "POST", "https://example.com/api", {"Accept": "application/json"},
        [{"name": "a", "value": "b"}], '{"x":1}', "json", "none", None, None,
        None, False, True, True, True, True,
    )
    command = result["command"]
    assert command.startswith("curl")
    assert "-L" in command
    assert "--compressed" in command
    assert "-i" in command
    assert "-s" in command
    assert "-H 'Accept: application/json'" in command


def test_generate_curl_pretty_breaks_into_lines(service: HTTPToolsService) -> None:
    result = service.generate_curl(
        "GET", "https://example.com/api", {}, [], None, "text", "none",
        None, None, None, True, False, False, False, False,
    )
    assert "\\\n" in result["command"]


def test_generate_headers_content_length(service: HTTPToolsService) -> None:
    result = service.generate_headers(
        [{"name": "Content-Type", "value": "application/json"}],
        "raw", True,
    )
    assert result["count"] == 1
    assert "Content-Type: application/json" in result["raw"]
    assert "Content-Length:" in result["raw"]


def test_generate_headers_duplicate_issue(service: HTTPToolsService) -> None:
    result = service.generate_headers(
        [{"name": "X-A", "value": "1"}, {"name": "x-a", "value": "2"}],
        "lowercase", False,
    )
    assert any(i["issue"] == "duplicate header name" for i in result["issues"])
    assert result["normalized"][0]["name"] == "x-a"


def test_parse_url_fields(service: HTTPToolsService) -> None:
    result = service.parse_url("https://u:p@example.com:8443/a?x=1&x=2#f")
    assert result["scheme"] == "https"
    assert result["host"] == "example.com"
    assert result["port"] == 8443
    assert result["username"] == "u"
    assert result["password"] == "p"
    assert result["params"] == {"x": "2"}
    assert result["fragment"] == "f"
