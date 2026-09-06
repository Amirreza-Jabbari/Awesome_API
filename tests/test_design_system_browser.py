"""Browser integration tests for the Design System Extractor.

These tests use a local fixture server and an explicit test-only SSRF guard that
allows loopback. Production code never relaxes the SSRF policy.
"""
from __future__ import annotations

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import pytest

from app.core.config import Settings
from app.core.exceptions import ResolutionBlockedError
from app.providers.web.ssrf import SSRFGuard
from app.services.design_system_service import BrowserManager, DesignSystemService


class _FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/runtime-design":
            body = b"""<!doctype html><html><head><style>body{font-family:Inter,sans-serif}.btn{padding:8px 16px;border-radius:10px}</style></head><body><button class='btn primary'>Buy</button><script>const s=document.createElement('style');s.textContent=':root{--color-primary:#2563eb} .btn{background:#2563eb;color:#fff}';document.head.appendChild(s)</script></body></html>"""
        elif path == "/redirect-private":
            self.send_response(302); self.send_header("Location", "http://127.0.0.1:1/"); self.end_headers(); return
        else:
            body = b"<html><body>fixture</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class _LoopbackGuard:
    """Test-only guard; production SSRF policy is never relaxed."""

    async def resolve_and_check(self, hostname: str) -> list[str]:
        if hostname in {"127.0.0.1", "localhost"}:
            return ["127.0.0.1"]
        raise ResolutionBlockedError("test-only guard blocks non-loopback targets")


@pytest.fixture
def fixture_server() -> str:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_runtime_css_is_detected(fixture_server: str) -> None:
    try:
        import playwright.async_api  # noqa: F401
    except ImportError:
        pytest.skip("Playwright is not installed")
    settings = Settings(app_env="test", cache_enabled=False, design_system_viewports=[{"width": 375, "height": 812}])
    guard = _LoopbackGuard()
    browser = BrowserManager(settings, guard)
    try:
        await browser.start()
    except Exception as exc:
        pytest.skip(f"Chromium is unavailable: {exc}")
    service = DesignSystemService(browser, guard, settings)
    try:
        result = await service.extract(f"{fixture_server}/runtime-design")
        assert "--color-primary" in result.design_system.custom_properties
        assert "button" in result.design_system.components
    finally:
        await browser.close()


@pytest.mark.asyncio
async def test_production_ssrf_guard_still_blocks_loopback(fake_dns) -> None:
    guard = SSRFGuard(fake_dns)
    with pytest.raises(ResolutionBlockedError):
        await guard.resolve_and_check("127.0.0.1")

class _FakeRequest:
    def __init__(self, url: str, resource_type: str = "stylesheet", method: str = "GET") -> None:
        self.url = url
        self.resource_type = resource_type
        self.method = method
        self.redirected_from = None
        self.headers = {}


class _FakeRoute:
    def __init__(self, request: _FakeRequest) -> None:
        self.request = request
        self.action = None

    async def abort(self, reason: str) -> None:
        self.action = ("abort", reason)

    async def continue_(self) -> None:
        self.action = ("continue",)


class _FakeContext:
    def __init__(self) -> None:
        self.handler = None

    async def route(self, pattern: str, handler: object) -> None:
        del pattern
        self.handler = handler


@pytest.mark.asyncio
async def test_browser_network_policy_blocks_private_destination(fake_dns) -> None:
    fake_dns.addr_table["internal.test"] = ["10.0.0.1"]
    from app.services.design_system_service import _ManagedContext

    settings = Settings(app_env="test", cache_enabled=False)
    context = _FakeContext()
    managed = _ManagedContext(context, asyncio.Semaphore(1), SSRFGuard(fake_dns), settings)
    await managed.install_network_policy()
    route = _FakeRoute(_FakeRequest("https://internal.test/app.css"))
    await context.handler(route)
    assert route.action == ("abort", "blockedbyclient")
    assert managed.blocked == 1
