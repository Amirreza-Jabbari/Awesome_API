"""API integration tests using an offline, fake-backed application.

A dedicated FastAPI app is built here (not the production singleton) and its
``request.app.state`` is populated with fake services so no request touches the
network. This exercises the real routes, middleware, exception handlers and the
JSON error envelope end-to-end.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import asynccontextmanager

import httpx
import pytest
from app.api.router import api_router
from app.core.config import Settings
from app.core.exceptions import AwesomeAPIError
from app.core.middleware import (
    RateLimitMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from app.core.ratelimit import build_rate_limiter
from app.providers.geoip.base import GeoIPResult
from app.providers.ipintel.base import IPIntelligence
from app.providers.web.ssrf import SSRFGuard
from app.repositories.cache import MemoryCache
from app.repositories.host_lists import (
    DisposableEmailRepository,
    HostListRepository,
    MaliciousHostRepository,
)
from app.services.cron_service import CronService
from app.services.data_tools_service import DataToolsService
from app.services.dev_tools_service import DevToolsService
from app.services.disposable_email_service import DisposableEmailService
from app.services.dns_service import DNSService
from app.services.domain_service import DomainService
from app.services.email_service import EmailValidationService
from app.services.http_tools_service import HTTPToolsService
from app.services.image_service import ImageService
from app.services.ip_service import IPService
from app.services.mock_data_service import MockDataGenerator
from app.services.mx_service import MXService
from app.services.password_service import PasswordService
from app.services.phone_service import PhoneValidationService
from app.services.toolbox_service import ToolboxService
from app.services.url_service import URLService
from app.services.user_agent_service import UserAgentService
from app.services.webpage_service import WebpageService
from app.services.whois_service import WhoIsService
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from .fakes import (
    FakeDNSProvider,
    FakeGeoIPProvider,
    FakeIPIntelligenceProvider,
    FakeRDPAProvider,
    FakeWhoIsProvider,
)

_PAGE = (
    "<html><head><title>Example Domain</title>"
    '<meta name="description" content="A test page"></head><body>hi</body></html>'
)


def _build_app() -> FastAPI:
    settings = Settings(app_env="test", cache_enabled=False, rate_limit_enabled=False)

    fake_dns = FakeDNSProvider()
    fake_geoip = FakeGeoIPProvider(
        GeoIPResult(country="United States", country_code="US", asn="AS15169", asn_name="GOOGLE")
    )
    fake_intel = FakeIPIntelligenceProvider(IPIntelligence(is_datacenter=True))
    cache = MemoryCache()
    rdap = FakeRDPAProvider()
    whois = FakeWhoIsProvider()

    disposable = DisposableEmailRepository({"guerrillamail.com"})
    free_hosts = HostListRepository({"gmail.com"})
    risky = HostListRepository({"top", "xyz"})
    malicious = MaliciousHostRepository({"evil.example.com"})

    whois_service = WhoIsService(rdap, whois, cache, settings)
    webpage_client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda req: httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                content=_PAGE.encode("utf-8"),
            )
        ),
        base_url="https://example.com",
    )

    tools_client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda req: httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                content=b'{"ok": true}',
            )
        ),
        base_url="https://example.com",
    )

    deps = {
        "settings": settings,
        "dns_provider": fake_dns,
        "cache": cache,
        "rate_limiter": build_rate_limiter(False, None),
        "ssrf_guard": SSRFGuard(fake_dns),
        "dns_service": DNSService(fake_dns, cache, settings),
        "mx_service": MXService(fake_dns, cache, settings),
        "disposable_email_service": DisposableEmailService(disposable),
        "email_service": EmailValidationService(
            dns_provider=fake_dns,
            disposable_domains=disposable,
            public_email_domains=free_hosts,
        ),
        "password_service": PasswordService(),
        "user_agent_service": UserAgentService(),
        "phone_service": PhoneValidationService(),
        "url_service": URLService(fake_dns, fake_geoip, cache, settings),
        "ip_service": IPService(fake_geoip, fake_intel, cache, settings),
        "whois_service": whois_service,
        "domain_service": DomainService(
            whois=whois_service,
            dns=fake_dns,
            geoip=fake_geoip,
            disposable=disposable,
            free_hosts=free_hosts,
            risky_tlds=risky,
            malicious=malicious,
            settings=settings,
        ),
        "webpage_service": WebpageService(webpage_client, SSRFGuard(fake_dns), settings),
        "toolbox_service": ToolboxService(),
        "data_tools_service": DataToolsService(),
        "dev_tools_service": DevToolsService(),
        "http_tools_service": HTTPToolsService(tools_client, SSRFGuard(fake_dns), settings),
        "mock_data_service": MockDataGenerator(),
        "cron_service": CronService(),
        "image_service": ImageService(settings),
    }

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        for key, value in deps.items():
            setattr(app.state, key, value)
        app.state.metrics = None
        yield
        await webpage_client.aclose()
        await tools_client.aclose()

    app = FastAPI(
        title="Awesome_API",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware, settings=settings)
    app.add_middleware(RequestContextMiddleware, settings=settings)

    @app.exception_handler(AwesomeAPIError)
    async def awesome_error_handler(request: Request, exc: AwesomeAPIError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": exc.code, "message": exc.message}},
        )

    @app.exception_handler(RequestValidationError)
    async def request_validation_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        errors = exc.errors()
        message = "The supplied input is invalid."
        if errors and "msg" in errors[0]:
            message = str(errors[0]["msg"])
        return JSONResponse(
            status_code=422,
            content={"error": {"code": "VALIDATION_ERROR", "message": message}},
        )

    @app.exception_handler(ValueError)
    async def value_error_handler(request: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": {"code": "VALIDATION_ERROR", "message": str(exc) or "Invalid input."}
            },
        )

    @app.get("/health", tags=["System"])
    async def health() -> dict[str, str]:
        return {"status": "healthy", "version": "1.0.0"}

    @app.get("/ready", tags=["System"])
    async def ready(request: Request) -> dict[str, object]:
        ready_now = hasattr(request.app.state, "dns_provider") and hasattr(
            request.app.state, "cache"
        )
        return {"status": "ready" if ready_now else "degraded"}

    @app.get("/version", tags=["System"])
    async def version() -> dict[str, str]:
        return {"name": "Awesome_API", "version": "1.0.0", "environment": "test"}

    app.include_router(api_router, prefix="/api/v1")

    return app


@pytest.fixture
def client() -> Iterator[TestClient]:
    app = _build_app()
    with TestClient(app) as test_client:
        yield test_client


def test_health(client) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "healthy"


def test_version(client) -> None:
    r = client.get("/version")
    assert r.status_code == 200
    assert r.json()["version"] == "1.0.0"


def test_ready(client) -> None:
    r = client.get("/ready")
    assert r.status_code == 200
    assert r.json()["status"] == "ready"


def test_password_generate(client) -> None:
    r = client.post("/api/v1/password/generate", json={"length": 20})
    assert r.status_code == 200
    assert len(r.json()["random_password"]) == 20


def test_password_impossible_config_422(client) -> None:
    r = client.post(
        "/api/v1/password/generate",
        json={"length": 4, "min_upper": 5, "min_lower": 5},
    )
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "VALIDATION_ERROR"


def test_disposable_check(client) -> None:
    r = client.post("/api/v1/email/disposable-check", json={"email": "x@guerrillamail.com"})
    assert r.status_code == 200
    assert r.json()["is_disposable"] is True


def test_dns_lookup(client) -> None:
    r = client.post("/api/v1/dns/lookup", json={"domain": "example.com", "record_types": ["A"]})
    assert r.status_code == 200
    types = {rec["record_type"] for rec in r.json()["records"]}
    assert types == {"A"}


def test_mx_lookup(client) -> None:
    r = client.post("/api/v1/mx/lookup", json={"domain": "gmail.com"})
    assert r.status_code == 200
    assert r.json()["records"]


def test_email_validate(client) -> None:
    r = client.post("/api/v1/email/validate", json={"email": "u@gmail.com"})
    assert r.status_code == 200
    assert r.json()["is_valid"] is True


def test_phone_validate(client) -> None:
    r = client.post("/api/v1/phone/validate", json={"number": "+14155552671"})
    assert r.status_code == 200
    assert r.json()["is_valid"] is True


def test_user_agent_parse(client) -> None:
    r = client.post(
        "/api/v1/user-agent/parse",
        json={
            "useragent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.89 "
            "Safari/537.36"
        },
    )
    assert r.status_code == 200
    assert r.json()["browser_family"] == "Chrome"


def test_ip_lookup(client) -> None:
    r = client.post("/api/v1/ip/lookup", json={"ip": "8.8.8.8"})
    assert r.status_code == 200
    assert r.json()["is_valid"] is True


def test_invalid_ip_422(client) -> None:
    r = client.post("/api/v1/ip/lookup", json={"ip": "not-an-ip"})
    assert r.status_code == 422


def test_ip_private_no_external_call(client) -> None:
    r = client.post("/api/v1/ip/lookup", json={"ip": "127.0.0.1"})
    assert r.status_code == 200
    body = r.json()
    assert body["is_loopback"] is True
    assert body["country"] is None


def test_url_lookup(client) -> None:
    r = client.post("/api/v1/url/lookup", json={"url": "example.com"})
    assert r.status_code == 200
    assert r.json()["is_valid"] is True


def test_invalid_url_error_envelope(client) -> None:
    r = client.post("/api/v1/url/lookup", json={"url": "http://localhost"})
    assert r.status_code == 422
    assert r.json()["error"]["code"] in ("INVALID_URL", "VALIDATION_ERROR")


def test_whois_lookup(client) -> None:
    r = client.post("/api/v1/whois/lookup", json={"domain": "example.com"})
    assert r.status_code == 200
    assert r.json()["source"] == "rdap"


def test_domain_lookup(client) -> None:
    r = client.post("/api/v1/domain/lookup", json={"domain": "github.com"})
    assert r.status_code == 200
    assert r.json()["available"] is False


def test_webpage_lookup(client) -> None:
    r = client.post("/api/v1/webpage/lookup", json={"url": "https://example.com"})
    assert r.status_code == 200
    assert r.json()["page_title"] == "Example Domain"


def test_invalid_body_field_422(client) -> None:
    r = client.post("/api/v1/password/generate", json={"length": "not-an-int"})
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "VALIDATION_ERROR"


def test_length_out_of_range_422(client) -> None:
    r = client.post("/api/v1/password/generate", json={"length": 1000})
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "VALIDATION_ERROR"


def test_unknown_route_404(client) -> None:
    r = client.get("/does-not-exist")
    assert r.status_code == 404


def test_invalid_domain_422(client) -> None:
    r = client.post("/api/v1/mx/lookup", json={"domain": "not a domain!"})
    assert r.status_code == 422
    assert r.json()["error"]["code"] in ("INVALID_DOMAIN", "VALIDATION_ERROR")


# ── New tool endpoints (offline) ────────────────────────────────────────────

def test_json_diff_api(client) -> None:
    r = client.post(
        "/api/v1/json/diff",
        json={"document_a": '{"a": 1, "b": 2}', "document_b": '{"a": 1, "c": 3}'},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["equal"] is False
    assert body["changes"]


def test_json_patch_api(client) -> None:
    r = client.post(
        "/api/v1/json/patch",
        json={"document_a": '{"name": "x"}', "document_b": '{"name": "y"}'},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["patch"]
    assert body["transformable"] is True


def test_yaml_convert_api(client) -> None:
    r = client.post(
        "/api/v1/yaml/convert",
        json={"direction": "json_to_yaml", "input": '{"a": 1, "b": [1, 2]}'},
    )
    assert r.status_code == 200
    assert r.json()["valid"] is True
    assert "a: 1" in r.json()["output"]


def test_xml_convert_api(client) -> None:
    r = client.post(
        "/api/v1/xml/convert",
        json={"direction": "json_to_xml", "input": '{"root": {"id": 5}}'},
    )
    assert r.status_code == 200
    assert r.json()["valid"] is True
    assert "<id>5</id>" in r.json()["output"]


def test_xml_entity_bomb_blocked_api(client) -> None:
    r = client.post(
        "/api/v1/xml/convert",
        json={
            "direction": "xml_to_json",
            "input": (
                '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e "x">]>'
                "<r>&e;</r>"
            ),
        },
    )
    assert r.status_code == 422


def test_http_headers_api(client) -> None:
    r = client.post(
        "/api/v1/http/headers",
        json={
            "headers": [{"name": "Content-Type", "value": "application/json"}],
            "style": "raw",
            "include_content_length": True,
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert "Content-Type: application/json" in body["raw"]
    assert body["count"] == 1


def test_http_curl_api(client) -> None:
    r = client.post(
        "/api/v1/http/curl",
        json={
            "method": "POST",
            "url": "https://example.com/api",
            "headers": {"X-Token": "abc"},
            "body_type": "json",
            "body": '{"x": 1}',
        },
    )
    assert r.status_code == 200
    command = r.json()["command"]
    assert command.startswith("curl")
    assert "https://example.com/api" in command


def test_url_parse_api(client) -> None:
    r = client.post(
        "/api/v1/url/parse",
        json={"url": "https://user:pass@example.com/a?x=1&x=2#frag"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["scheme"] == "https"
    assert body["hostname"] == "example.com"
    assert body["params"]["x"] == "2"
    assert body["username"] == "user"


def test_json_diff_overflow_error(client) -> None:
    r = client.post(
        "/api/v1/json/diff",
        json={"document_a": '{"a": 1}', "document_b": "not json"},
    )
    assert r.status_code == 422


def test_sql_format_api(client) -> None:
    r = client.post(
        "/api/v1/sql/format",
        json={"sql": "SELECT * FROM users WHERE id=1", "keyword_case": "upper"},
    )
    assert r.status_code == 200
    assert r.json()["valid"] is True


def test_sql_minify_api(client) -> None:
    r = client.post(
        "/api/v1/sql/minify",
        json={"sql": "SELECT 1 -- c", "strip_comments": True},
    )
    assert r.status_code == 200
    assert r.json()["removed_comments"] >= 1


def test_sql_validate_api(client) -> None:
    r = client.post(
        "/api/v1/sql/validate",
        json={"sql": "SELECT (1"},
    )
    assert r.status_code == 200
    assert r.json()["valid"] is False


def test_semver_api(client) -> None:
    r = client.post(
        "/api/v1/semver/analyze",
        json={"version": "1.2.3", "other": "1.2.4", "range": ">=1.0.0"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["valid"] is True
    assert body["comparison"]["comparable"] is True
    assert body["range_result"]["matches"] is True


def test_changelog_api(client) -> None:
    r = client.post(
        "/api/v1/changelog/generate",
        json={
            "commits": [
                {"type": "feat", "description": "add widgets"},
                {"type": "fix", "description": "repair the gadget"},
                {"type": "feat", "description": "explode", "breaking": True},
            ],
            "version": "1.0.0",
            "date": "2026-09-05",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert "widgets" in body["markdown"]
    assert "Breaking Changes" in body["markdown"]


def test_color_convert_api(client) -> None:
    r = client.post(
        "/api/v1/color/convert",
        json={"color": "#ff0000", "from_format": "hex", "background": "#ffffff"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["hex"] == "#ff0000"
    assert body["rgb"]["r"] == 255
    assert body["hsl"]["lightness"] == 50


def test_mock_generate_api(client) -> None:
    r = client.post(
        "/api/v1/mock/generate",
        json={
            "schema": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "email": {"type": "string", "format": "email"},
                },
            },
            "seed": 7,
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body["value"]["id"], int)
    assert "@" in body["value"]["email"]
    assert body["type"] == "object"


def test_mock_openapi_api(client) -> None:
    doc = (
        "openapi: 3.0.3\n"
        "info:\n  title: t\n  version: 1.0.0\n"
        "paths:\n  /users:\n    get:\n      responses:\n        '200':\n"
        "          description: ok\n          content:\n            application/json:\n"
        "              schema:\n                type: object\n"
        "                properties:\n                  name:\n                    type: string\n"
    )
    r = client.post(
        "/api/v1/mock/openapi",
        json={"document": doc, "path": "/users", "method": "get", "seed": 3},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["valid"] is True
    assert isinstance(body["content"].get("name"), str)


def test_cron_generate_api(client) -> None:
    r = client.post(
        "/api/v1/cron/generate",
        json={"schedule": "every 5 minutes"},
    )
    assert r.status_code == 200
    assert r.json()["expression"] == "*/5 * * * *"


def test_cron_parse_api(client) -> None:
    r = client.post(
        "/api/v1/cron/parse",
        json={
            "expression": "*/10 * * * *",
            "count": 3,
            "reference_timestamp": 1757088000,
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["valid"] is True
    assert len(body["next_times"]) == 3


def test_cron_parse_invalid_api(client) -> None:
    r = client.post(
        "/api/v1/cron/parse",
        json={"expression": "99 * * * *", "count": 3},
    )
    assert r.status_code == 200
    assert r.json()["valid"] is False


def test_jwt_generate_api(client) -> None:
    r = client.post(
        "/api/v1/jwt/generate",
        json={
            "payload": {"role": "admin"},
            "algorithm": "HS256",
            "secret": "this-is-a-very-secure-secret-value-42",
            "subject": "uid-1",
            "expires_in": 120,
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["token"].count(".") == 2
    assert body["algorithm"] == "HS256"
    assert body["payload"]["sub"] == "uid-1"
    assert body["expires_in"] == 120


def test_jwt_generate_weak_secret_422(client) -> None:
    r = client.post(
        "/api/v1/jwt/generate",
        json={"payload": {}, "algorithm": "HS256", "secret": "short"},
    )
    assert r.status_code == 422


def test_http_request_execute_api(client) -> None:
    r = client.post(
        "/api/v1/http/request",
        json={
            "request": {
                "method": "GET",
                "url": "https://example.com/data",
                "query": [{"name": "q", "value": "1"}],
            },
            "execute": True,
            "timeout": 5.0,
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["mode"] == "execute"
    assert body["status_code"] == 200
    assert body["is_json"] is True
    assert body["ssrf_checked"] is True


def test_http_request_execute_ssrf_blocked_api(client) -> None:
    r = client.post(
        "/api/v1/http/request",
        json={
            "request": {"method": "GET", "url": "http://127.0.0.1:8080/"},
            "execute": True,
            "timeout": 5.0,
        },
    )
    assert r.status_code == 200
    assert r.json()["error"] is not None


def test_http_inspect_api(client) -> None:
    r = client.post(
        "/api/v1/http/inspect",
        json={
            "url": "https://example.com/",
            "method": "GET",
            "follow_redirects": False,
            "max_body_size": 2048,
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["valid"] is True
    assert body["status_code"] == 200
    assert body["is_json"] is True


def test_tools_schema_present(client) -> None:
    spec = client.get("/openapi.json").json()
    paths = spec["paths"]
    expected = [
        "/api/v1/json/diff",
        "/api/v1/cron/parse",
        "/api/v1/mock/openapi",
        "/api/v1/http/request",
        "/api/v1/jwt/generate",
    ]
    for path in expected:
        assert path in paths
