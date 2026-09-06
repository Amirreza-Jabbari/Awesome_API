"""Tests for the webpage metadata extraction service."""

from __future__ import annotations

import httpx
import pytest
from app.core.exceptions import (
    ProviderTimeoutError,
    ResolutionBlockedError,
    ResourceLimitError,
)
from app.providers.web.ssrf import SSRFGuard
from app.services.webpage_service import WebpageService

_HTML = (
    "<!DOCTYPE html><html><head>"
    "<title>Example Domain</title>"
    '<meta name="description" content="A test page">'
    '<link rel="icon" href="/favicon.ico"></head>'
    "<body><h1>Hello</h1></body></html>"
)


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _svc(client, fake_dns, settings) -> WebpageService:
    return WebpageService(client, SSRFGuard(fake_dns), settings)


async def _extract(handler, fake_dns, settings, url: str = "https://example.com") -> dict:
    client = _client(handler)
    try:
        svc = _svc(client, fake_dns, settings)
        return await svc.extract(url)
    finally:
        await client.aclose()


async def test_successful_html(fake_dns, settings) -> None:
    result = await _extract(
        lambda req: httpx.Response(
            200, headers={"Content-Type": "text/html"}, content=_HTML.encode()
        ),
        fake_dns,
        settings,
    )
    assert result["page_title"] == "Example Domain"
    assert result["page_description"] == "A test page"
    assert result["favicon"] is not None
    assert result["domain"] == "example.com"


async def test_redirect_followed(fake_dns, settings) -> None:
    async def handler(req):
        if req.url.path == "/redirect":
            return httpx.Response(302, headers={"Location": "https://example.com/final"})
        return httpx.Response(200, headers={"Content-Type": "text/html"}, content=_HTML.encode())

    result = await _extract(handler, fake_dns, settings, "https://example.com/redirect")
    assert result["url"] == "https://example.com/final"


async def test_redirect_to_private_ip_blocked(fake_dns, settings) -> None:
    fake_dns.addr_table.update({"private.test": ["10.0.0.1"]})

    async def handler(req):
        return httpx.Response(302, headers={"Location": "https://private.test/"})

    with pytest.raises(ResolutionBlockedError):
        await _extract(handler, fake_dns, settings)


async def test_blocked_private_ip(fake_dns, settings) -> None:
    fake_dns.addr_table.update({"private.test": ["10.0.0.1"]})
    with pytest.raises(ResolutionBlockedError):
        await _extract(lambda req: httpx.Response(200), fake_dns, settings, "https://private.test")


async def test_oversized_response(fake_dns, settings) -> None:
    settings.webpage_max_response_size = 100

    async def handler(req):
        return httpx.Response(
            200,
            headers={"Content-Type": "text/html"},
            content=b"x" * 1000,
        )

    with pytest.raises(ResourceLimitError):
        await _extract(handler, fake_dns, settings)


async def test_timeout(fake_dns, settings) -> None:
    async def handler(req):
        raise httpx.ReadTimeout("timeout")

    with pytest.raises(ProviderTimeoutError):
        await _extract(handler, fake_dns, settings)


async def test_missing_title(fake_dns, settings) -> None:
    body = "<html><head></head><body>no title here</body></html>"
    result = await _extract(
        lambda req: httpx.Response(
            200, headers={"Content-Type": "text/html"}, content=body.encode()
        ),
        fake_dns,
        settings,
    )
    assert result["page_title"] is None


async def test_non_html_content_type(fake_dns, settings) -> None:
    result = await _extract(
        lambda req: httpx.Response(
            200, headers={"Content-Type": "application/json"}, content=b'{"a":1}'
        ),
        fake_dns,
        settings,
    )
    # Non-HTML bodies are not parsed; title stays None.
    assert result["page_title"] is None
