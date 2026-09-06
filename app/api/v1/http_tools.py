"""Web & HTTP endpoints: request builder/executor, inspector, curl, headers, URL."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from app.core.dependencies import get_http_tools_service
from app.schemas.http_tools import (
    CurlGenerateRequest,
    CurlGenerateResponse,
    HeadersGenerateRequest,
    HeadersGenerateResponse,
    HTTPInspectRequest,
    HTTPInspectResponse,
    HTTPRequestBuilderRequest,
    HTTPRequestBuilderResponse,
    URLParseRequest,
    URLParseResponse,
)
from app.services.http_tools_service import HTTPToolsService

router = APIRouter()


# ── HTTP Request Builder / Executor ──────────────────────────────────────────

@router.post(
    "/http/request",
    response_model=HTTPRequestBuilderResponse,
    tags=["Web & HTTP"],
    summary="Build or execute an HTTP request",
    description=(
        "Constructs a canonical HTTP request (headers, URL-safe query string, "
        "body encoding, optional Basic/Bearer authorization) and returns its "
        "curl equivalent. With execute=true the request is actually sent - the "
        "target is resolved through the SSRF guard (private/internal addresses "
        "are blocked) and every redirect hop is re-validated. Credentials are "
        "never logged or persisted."
    ),
)
async def http_request(
    payload: HTTPRequestBuilderRequest,
    service: HTTPToolsService = Depends(get_http_tools_service),
) -> dict[str, Any]:
    spec = payload.request
    query: list[dict[str, str]] = [
        {"name": param.name, "value": param.value} for param in spec.query
    ]
    if not payload.execute:
        return service.build_request(
            spec.method, spec.url, spec.headers, query, spec.body, spec.body_type,
            spec.auth.type, spec.auth.username, spec.auth.password, spec.auth.token,
        )
    return await service.execute(
        spec.method, spec.url, spec.headers, query, spec.body, spec.body_type,
        spec.auth.type, spec.auth.username, spec.auth.password, spec.auth.token,
        payload.timeout,
    )


# ── HTTP Inspector ───────────────────────────────────────────────────────────

@router.post(
    "/http/inspect",
    response_model=HTTPInspectResponse,
    tags=["Web & HTTP"],
    summary="Inspect an HTTP request",
    description=(
        "Performs a live HTTP request and reports the response: status, reason, "
        "headers, cookies, content type and charset, a truncated body preview, "
        "JSON detection and redirect history. The host is SSRF-checked before "
        "connecting and on every redirect; response size is capped."
    ),
)
async def http_inspect(
    payload: HTTPInspectRequest,
    service: HTTPToolsService = Depends(get_http_tools_service),
) -> dict[str, Any]:
    return await service.inspect(
        payload.url, payload.method, payload.headers, payload.body,
        payload.follow_redirects, payload.max_redirects, payload.max_body_size,
        payload.timeout,
    )


# ── Curl Generator ───────────────────────────────────────────────────────────

@router.post(
    "/http/curl",
    response_model=CurlGenerateResponse,
    tags=["Web & HTTP"],
    summary="Generate a curl command",
    description=(
        "Renders a ready-to-paste curl command for the given request without "
        "performing any network I/O. Supports formatted/multi-line output, "
        "response-header display (-i), redirect following (-L), compression "
        "(--compressed) and silent mode (-s)."
    ),
)
async def curl_generate(
    payload: CurlGenerateRequest,
    service: HTTPToolsService = Depends(get_http_tools_service),
) -> dict[str, Any]:
    query = [h.model_dump() for h in payload.query]
    return service.generate_curl(
        payload.method, payload.url, payload.headers, query, payload.body,
        payload.body_type, payload.auth.type, payload.auth.username,
        payload.auth.password, payload.auth.token, payload.pretty,
        payload.include_headers, payload.follow_redirects, payload.compressed,
        payload.silent,
    )


# ── Headers Generator ────────────────────────────────────────────────────────

@router.post(
    "/http/headers",
    response_model=HeadersGenerateResponse,
    tags=["Web & HTTP"],
    summary="Generate raw HTTP header lines",
    description=(
        "Builds raw HTTP/1.1-style header lines from name/value pairs, with "
        "optional lowercase/uppercase normalization, duplicate detection and an "
        "optional computed Content-Length. Pure local formatting - nothing is sent."
    ),
)
async def headers_generate(
    payload: HeadersGenerateRequest,
    service: HTTPToolsService = Depends(get_http_tools_service),
) -> dict[str, Any]:
    pairs = [{"name": h.name, "value": h.value} for h in payload.headers]
    return service.generate_headers(pairs, payload.style, payload.include_content_length)


# ── URL Parser ───────────────────────────────────────────────────────────────

@router.post(
    "/url/parse",
    response_model=URLParseResponse,
    tags=["Web & HTTP"],
    summary="Parse and dissect a URL",
    description=(
        "Splits a URL into scheme, host, port, path, fragment and query-string "
        "parameters (paired and as a dict). Userinfo credentials, if present, are "
        "reported separately; executed requests reject them for security."
    ),
)
async def url_parse(
    payload: URLParseRequest,
    service: HTTPToolsService = Depends(get_http_tools_service),
) -> dict[str, Any]:
    return service.parse_url(payload.url)
