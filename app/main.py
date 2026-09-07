"""FastAPI application entry point and dependency wiring.

Assembles configuration, logging, middleware, exception handlers, health
endpoints and service/provider instances. Service construction happens once at
startup and is exposed via ``request.app.state``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.router import API_V1_PREFIX, api_router
from app.core.config import Settings, get_settings
from app.core.exceptions import AwesomeAPIError
from app.core.health import HealthService
from app.core.logging import configure_logging, get_logger
from app.core.metrics import NoopMetrics, build_metrics
from app.core.middleware import (
    RateLimitMiddleware,
    RequestContextMiddleware,
    RequestLimitMiddleware,
    SecurityHeadersMiddleware,
)
from app.core.openapi import customize_openapi
from app.core.ratelimit import build_rate_limiter
from app.providers.dns.dns_python import DNSPythonProvider
from app.providers.geoip.base import GeoIPProvider
from app.providers.geoip.free import FreeIPIntelligenceProvider
from app.providers.geoip.ip_api import IpApiGeoIPProvider
from app.providers.geoip.maxmind import MaxMindGeoIPProvider
from app.providers.geoip.none import NullGeoIPProvider
from app.providers.ipintel.null import NullIPIntelligenceProvider
from app.providers.web.ssrf import SSRFGuard, SSRFHttpTransport
from app.providers.whois.rdap_provider import RDAPProvider
from app.providers.whois.whois_provider import PythonWhoisProvider
from app.repositories.cache import Cache, MemoryCache, NullCache, RedisCache
from app.repositories.host_lists import (
    DisposableEmailRepository,
    HostListRepository,
    MaliciousHostRepository,
)
from app.services.browser_intelligence_service import (
    AccessibilityAuditService,
    APIDiscoveryService,
    CoreWebVitalsService,
    ScreenshotService,
)
from app.services.cron_service import CronService
from app.services.data_tools_service import DataToolsService
from app.services.design_system_service import BrowserManager, DesignSystemService
from app.services.dev_tools_service import DevToolsService
from app.services.disposable_email_service import DisposableEmailService
from app.services.dns_service import DNSService
from app.services.dns_tools_service import DNSToolsService
from app.services.domain_service import DomainService
from app.services.email_service import EmailValidationService
from app.services.file_metadata_service import FileMetadataService
from app.services.http_tools_service import HTTPToolsService
from app.services.ip_service import IPService
from app.services.mock_data_service import MockDataGenerator
from app.services.mx_service import MXService
from app.services.password_service import PasswordService
from app.services.phone_service import PhoneValidationService
from app.services.toolbox_service import ToolboxService
from app.services.url_service import URLService
from app.services.user_agent_service import UserAgentService
from app.services.web_tools_service import WebToolsService
from app.services.webpage_service import WebpageService
from app.services.whois_service import WhoIsService

logger = get_logger(__name__)

settings = get_settings()


def _build_geoip(settings: Settings, http_client: httpx.AsyncClient) -> GeoIPProvider:
    """Construct the configured GeoIP provider."""
    provider = settings.geoip_provider
    if provider == "free":
        return FreeIPIntelligenceProvider(http_client, timeout=settings.http_timeout)
    if provider == "ip-api":
        return IpApiGeoIPProvider(http_client, timeout=settings.http_timeout)
    if provider == "maxmind":
        # Database path is supplied via GEOIP_API_KEY for flexibility; an
        # otherwise-empty value yields a clear configuration error on use.
        return MaxMindGeoIPProvider(db_path=settings.geoip_api_key)
    return NullGeoIPProvider()


def build_providers(settings: Settings) -> dict[str, Any]:
    """Construct all services/providers. Exposed for tests and startup."""
    transport = SSRFHttpTransport(
        verify=True,
        trust_env=False,
        limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        retries=0,
    )
    http_client = httpx.AsyncClient(
        transport=transport,
        timeout=httpx.Timeout(settings.http_timeout),
        follow_redirects=True,
        trust_env=False,
    )

    metrics = build_metrics(settings)
    if settings.cache_enabled:
        if settings.redis_url:
            cache: Cache = RedisCache(settings.redis_url)
        else:
            cache = MemoryCache(settings.cache_max_entries, metrics=metrics)
    else:
        cache = NullCache()

    # Verify Redis connectivity up front; fall back to in-memory when it is
    # not reachable (dev/test friendliness, and fail-open for caching).
    redis_usable = settings.redis_url and settings.app_env != "test"
    if redis_usable:
        import redis

        try:
            probe = redis.Redis.from_url(
                settings.redis_url, socket_connect_timeout=1.5, socket_timeout=1.5
            )
            probe.ping()
            probe.close()
            redis_usable = True
        except Exception:
            logger.warning("redis unavailable; falling back to in-memory cache/rate-limiter")
            redis_usable = False

    if settings.cache_enabled and isinstance(cache, RedisCache) and not redis_usable:
        cache = MemoryCache(settings.cache_max_entries, metrics=metrics)

    rate_limiter = build_rate_limiter(
        settings.rate_limit_enabled,
        settings.redis_url if redis_usable else None,
        max_keys=settings.rate_limit_max_keys,
    )

    dns_provider = DNSPythonProvider(
        nameservers=settings.dns_nameserver_list,
        timeout=settings.dns_timeout,
        lifetime=settings.dns_lifetime,
    )

    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    data_dir = root / "data"
    disposable_repo = DisposableEmailRepository.from_file("disposable_hosts.txt")
    free_hosts = HostListRepository.from_file(str(data_dir / "free_email_hosts.txt"))
    risky_tlds = HostListRepository.from_file(str(data_dir / "risky_tlds.txt"))
    malicious_repo = MaliciousHostRepository.from_file("malicious_hosts.txt")

    geoip = _build_geoip(settings, http_client)
    intel = NullIPIntelligenceProvider()

    dns_service = DNSService(dns_provider, cache, settings, metrics=metrics)
    mx_service = MXService(dns_provider, cache, settings, metrics=metrics)
    disposable_service = DisposableEmailService(disposable_repo)
    email_service = EmailValidationService(
        dns_provider=dns_provider,
        disposable_domains=disposable_repo,
        public_email_domains=free_hosts,
    )
    password_service = PasswordService()
    user_agent_service = UserAgentService()
    phone_service = PhoneValidationService()

    ssrf_guard = SSRFGuard(dns_provider)
    rdap = RDAPProvider(http_client, settings, guard=ssrf_guard)
    whois_prov = PythonWhoisProvider(settings)
    whois_service = WhoIsService(rdap, whois_prov, cache, settings, metrics=metrics)
    domain_service = DomainService(
        whois=whois_service,
        dns=dns_provider,
        geoip=geoip,
        disposable=disposable_repo,
        free_hosts=free_hosts,
        risky_tlds=risky_tlds,
        malicious=malicious_repo,
        settings=settings,
        metrics=metrics,
    )

    # Reuse the single shared HTTP client. SSRF-sensitive fetchers explicitly
    # disable automatic redirects and validate each destination hop.
    webpage_service = WebpageService(http_client, ssrf_guard, settings, metrics=metrics)
    browser_manager = BrowserManager(settings, ssrf_guard)
    design_system_service = DesignSystemService(
        browser_manager, ssrf_guard, settings, cache=cache, metrics=metrics
    )
    accessibility_audit_service = AccessibilityAuditService(
        browser_manager, ssrf_guard, settings, cache=cache
    )
    core_web_vitals_service = CoreWebVitalsService(
        browser_manager, ssrf_guard, settings, cache=cache
    )
    screenshot_service = ScreenshotService(browser_manager, ssrf_guard, settings, cache=cache)
    api_discovery_service = APIDiscoveryService(browser_manager, ssrf_guard, settings, cache=cache)

    ip_service = IPService(geoip, intel, cache, settings, metrics=metrics)
    url_service = URLService(dns_provider, geoip, cache, settings, metrics=metrics)
    toolbox_service = ToolboxService()

    data_tools_service = DataToolsService()
    dev_tools_service = DevToolsService()
    http_tools_service = HTTPToolsService(http_client, ssrf_guard, settings, metrics=metrics)
    mock_data_service = MockDataGenerator()
    cron_service = CronService()

    return {
        "http_client": http_client,
        "dns_provider": dns_provider,
        "cache": cache,
        "cache_backend": "redis" if isinstance(cache, RedisCache) else "memory",
        "health_service": HealthService(settings),
        "metrics": metrics,
        "rate_limiter": rate_limiter,
        "ssrf_guard": ssrf_guard,
        "dns_service": dns_service,
        "mx_service": mx_service,
        "disposable_email_service": disposable_service,
        "email_service": email_service,
        "password_service": password_service,
        "user_agent_service": user_agent_service,
        "phone_service": phone_service,
        "whois_service": whois_service,
        "domain_service": domain_service,
        "webpage_service": webpage_service,
        "browser_manager": browser_manager,
        "design_system_service": design_system_service,
        "accessibility_audit_service": accessibility_audit_service,
        "core_web_vitals_service": core_web_vitals_service,
        "screenshot_service": screenshot_service,
        "api_discovery_service": api_discovery_service,
        "ip_service": ip_service,
        "url_service": url_service,
        "toolbox_service": toolbox_service,
        "web_tools_service": WebToolsService(webpage_service, ssrf_guard, ip_service),
        "dns_tools_service": DNSToolsService(dns_provider, disposable_repo, free_hosts),
        "file_metadata_service": FileMetadataService(),
        "data_tools_service": data_tools_service,
        "dev_tools_service": dev_tools_service,
        "http_tools_service": http_tools_service,
        "mock_data_service": mock_data_service,
        "cron_service": cron_service,
        # Repositories shared with services.
        "disposable_email_repository": disposable_repo,
        "free_email_hosts_repository": free_hosts,
    }


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    configure_logging(settings)
    deps = build_providers(settings)
    for key, value in deps.items():
        setattr(app.state, key, value)
    app.state.settings = settings
    browser_manager = getattr(app.state, "browser_manager", None)
    if browser_manager is not None and settings.design_system_enabled:
        try:
            await browser_manager.start()
        except Exception:
            # Keep core API startup available; the design-system endpoint returns a controlled 503.
            logger.exception(
                "design_system_browser_start_failed",
                extra={"include_traceback": settings.debug},
            )
    logger.info(
        "startup_complete env=%s geoip_provider=%s cache=%s rate_limit=%s",
        settings.app_env,
        settings.geoip_provider,
        settings.cache_enabled,
        settings.rate_limit_enabled,
    )
    yield
    for key in ("http_client",):
        client = getattr(app.state, key, None)
        if client is not None:
            await client.aclose()
    browser_manager = getattr(app.state, "browser_manager", None)
    if browser_manager is not None:
        await browser_manager.close()
    cache = getattr(app.state, "cache", None)
    if cache is not None and hasattr(cache, "close"):
        await cache.close()

    rate_limiter = getattr(app.state, "rate_limiter", None)
    if rate_limiter is not None and hasattr(rate_limiter, "close"):
        await rate_limiter.close()

    logger.info("shutdown_complete")


_openapi_tags = [
    {
        "name": "System",
        "description": "Liveness, readiness, version and Prometheus metrics endpoints.",
    },
    {
        "name": "Email",
        "description": (
            "Email utilities: disposable-email detection, syntax/MX validation, "
            "raw email-header analysis and email-domain (MX/SPF/DMARC) analysis."
        ),
    },
    {
        "name": "Domain & DNS",
        "description": (
            "Domain and DNS utilities: DNS, MX, WHOIS/RDAP and DNSSEC lookups and "
            "aggregated domain intelligence."
        ),
    },
    {
        "name": "IP & Network",
        "description": (
            "IP and network utilities: IPv4/IPv6 validation, GeoIP/ASN intelligence, "
            "URL host resolution and TCP port-status checks."
        ),
    },
    {
        "name": "Web Analysis",
        "description": (
            "Web analysis: browser-rendered design-system extraction, accessibility "
            "auditing, synthetic "
            "Core Web Vitals, screenshots, API discovery, webpage metadata, user-agent parsing, "
            "robots.txt, sitemap, "
            "Open Graph, website-technology detection, redirect tracing and canonical URLs."
        ),
    },
    {
        "name": "Web Security",
        "description": (
            "Web security: JWT inspection/generation, HTTP/security header analysis "
            "and SSL/TLS certificate lookups."
        ),
    },
    {
        "name": "Web & HTTP",
        "description": (
            "Web and HTTP utilities: request building/execution, live response "
            "inspection, curl command generation, raw header generation and URL parsing."
        ),
    },
    {
        "name": "Developer Tools",
        "description": (
            "Developer utilities: SQL formatting/minification/validation, SemVer "
            "analysis, changelog generation, color conversion and mock-data generation "
            "from schemas and OpenAPI documents."
        ),
    },
    {
        "name": "Data & Encoding",
        "description": (
            "Data and encoding utilities: hashing, Base64/URL/HTML codecs, UUID/ULID, "
            "JSON formatting and Unicode inspection."
        ),
    },
    {
        "name": "Validation & Text",
        "description": (
            "Validation and text utilities: password generation and strength analysis, "
            "phone validation and regex testing."
        ),
    },
    {
        "name": "Files & Metadata",
        "description": (
            "File and metadata utilities: magic-byte file-type detection, content-type "
            "detection and image metadata (EXIF/ICC) extraction."
        ),
    },
    {
        "name": "Time & Date",
        "description": "Time and date utilities: timestamp conversion and timezone lookup.",
    },
]

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "A production-ready collection of developer, security and networking "
        "utilities: disposable-email checking, DNS/MX/WHOIS/RDAP lookups, "
        "domain/IP/URL intelligence, password generation, user-agent parsing, "
        "email/phone validation, developer/security utilities and webpage analysis."
    ),
    openapi_tags=_openapi_tags,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

app.openapi = lambda: customize_openapi(app)  # type: ignore[method-assign]


@app.get("/health", response_model=dict, tags=["System"], summary="Liveness probe")
async def health() -> dict[str, str]:
    return {"status": "healthy", "version": settings.app_version}


@app.get("/ready", response_model=dict, tags=["System"], summary="Readiness probe")
async def ready(request: Request) -> dict[str, Any]:
    diagnostics = await request.app.state.health_service.readiness(request.app.state)
    readiness = {
        name: check["status"] in {"healthy", "degraded"}
        for name, check in diagnostics["checks"].items()
        if name in {"dns", "cache"}
    }
    # Preserve the existing readiness map while exposing safe diagnostic detail.
    return {
        "status": "ready" if diagnostics["status"] == "healthy" else "degraded",
        "readiness": readiness,
        "diagnostics": diagnostics["checks"],
    }


@app.get("/version", response_model=dict, tags=["System"], summary="Application version")
async def version() -> dict[str, str]:
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "environment": settings.app_env,
    }


if settings.metrics_enabled:

    @app.get("/metrics", include_in_schema=False, tags=["System"])
    async def metrics() -> Response:
        # Prometheus exposition is not JSON; JSONResponse would quote the
        # entire payload and make /metrics invalid for Prometheus scrapers.
        return Response(
            content=generate_latest(),
            media_type=CONTENT_TYPE_LATEST,
        )


# Middleware
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestLimitMiddleware, settings=settings)
app.add_middleware(RateLimitMiddleware, settings=settings)
app.add_middleware(RequestContextMiddleware, settings=settings)
if get_settings().cors_origin_list:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=get_settings().cors_origin_list,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
        max_age=86400,
    )


# Exception handlers --------------------------------------------------------


@app.exception_handler(AwesomeAPIError)
async def awesome_api_error_handler(request: Request, exc: AwesomeAPIError) -> JSONResponse:
    metrics = getattr(request.app.state, "metrics", NoopMetrics())
    metrics.inc_error(exc.code)
    if exc.code == "SSRF_BLOCKED" or exc.code == "RESOLUTION_BLOCKED":
        metrics.inc_security_rejection(exc.code.lower())
    request_id = request_id_for_response(request)
    logger.info("handled_error code=%s", exc.code)
    public_message = (
        exc.default_message
        if exc.status_code >= 502 or exc.code in {"SSRF_BLOCKED", "RESOLUTION_BLOCKED"}
        else exc.message
    )
    error: dict[str, Any] = {
        "code": exc.code,
        "message": public_message,
        "request_id": request_id,
    }
    if exc.details is not None:
        error["details"] = exc.details
    return JSONResponse(status_code=exc.status_code, content={"error": error})


@app.exception_handler(RequestValidationError)
async def request_validation_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    metrics = getattr(request.app.state, "metrics", NoopMetrics())
    metrics.inc_error("VALIDATION_ERROR")
    # Never expose Pydantic internals, field values, or parser traces.
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "VALIDATION_ERROR",
                "message": "The supplied input is invalid.",
                "request_id": request_id_for_response(request),
            }
        },
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(
    request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    code = {
        404: "NOT_FOUND",
        405: "METHOD_NOT_ALLOWED",
        401: "UNAUTHORIZED",
        403: "FORBIDDEN",
    }.get(exc.status_code, "HTTP_ERROR")
    message = {
        404: "The requested resource was not found.",
        405: "The HTTP method is not allowed for this resource.",
        401: "Authentication is required.",
        403: "Access to this resource is forbidden.",
    }.get(exc.status_code, "The HTTP request could not be completed.")
    metrics = getattr(request.app.state, "metrics", NoopMetrics())
    metrics.inc_error(code)
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": code,
                "message": message,
                "request_id": request_id_for_response(request),
            }
        },
    )


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError) -> JSONResponse:
    del exc
    metrics = getattr(request.app.state, "metrics", NoopMetrics())
    metrics.inc_error("VALIDATION_ERROR")
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "VALIDATION_ERROR",
                "message": "The supplied input is invalid.",
                "request_id": request_id_for_response(request),
            }
        },
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    del exc
    metrics = getattr(request.app.state, "metrics", NoopMetrics())
    metrics.inc_error("INTERNAL_ERROR")
    logger.exception("unhandled_exception", extra={"include_traceback": settings.debug})
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "An internal error occurred.",
                "request_id": request_id_for_response(request),
            }
        },
    )


def request_id_for_response(request: Request) -> str:
    from app.core.middleware import get_request_id

    return (
        get_request_id()
        or request.scope.get("request_id")
        or request.headers.get("X-Request-ID", "").strip()
        or "unassigned"
    )


app.include_router(api_router, prefix=API_V1_PREFIX)


@app.get("/", include_in_schema=False)
async def root() -> dict[str, str]:
    return {"name": settings.app_name, "version": settings.app_version, "docs": "/docs"}
