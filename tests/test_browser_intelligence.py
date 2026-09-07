"""Deterministic unit/integration coverage for browser intelligence APIs."""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import pytest
from app.core.config import Settings
from app.services.browser_intelligence_service import (
    AccessibilityAuditService,
    APIDiscoveryService,
    CoreWebVitalsService,
    ScreenshotService,
    contrast_ratio,
)
from app.services.design_system_service import BrowserManager


def test_contrast_ratio_is_wcag_compliant() -> None:
    assert round(contrast_ratio("#333333", "#ffffff") or 0, 2) == 12.63
    assert (contrast_ratio("#777777", "#ffffff") or 0) < 4.5


def test_browser_intelligence_settings_are_bounded() -> None:
    settings = Settings(
        app_env="test",
        cache_enabled=False,
        screenshot_max_width=2000,
        screenshot_max_height=1200,
        screenshot_default_width=1440,
        screenshot_default_height=900,
    )
    assert settings.screenshot_max_width == 2000
    assert settings.api_discovery_max_probes <= len(settings.api_discovery_well_known_paths)


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            body = (
                b"""<!doctype html><html lang='en'><head><title>Fixture</title>"""
                b"""<style>body{color:#333;background:#fff}"""
                b"""button{background:#123;color:#fff}</style></head><body><main><h1>Fixture</h1>"""
                b"<img src='/missing'><button>Run</button>"
                b"<script>const s=document.createElement('style');"
                b"""s.textContent=':root{--runtime:#2563eb}';document.head.appendChild(s);"""
                b"""fetch('/api/data').catch(()=>{});</script></main></body></html>"""
            )
        elif path == "/api/data":
            body = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        elif path == "/openapi.json":
            body = b'{"openapi":"3.0.0","info":{"title":"Fixture","version":"1"},"paths":{}}'
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html" if path == "/" else "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


@pytest.fixture
def fixture_server() -> str:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
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
async def test_all_browser_intelligence_apis_use_browser_fixture(fixture_server: str) -> None:
    class LoopbackGuard:
        async def resolve_and_check(self, hostname: str) -> list[str]:
            if hostname == "127.0.0.1":
                return [hostname]
            raise RuntimeError("blocked")

    settings = Settings(
        app_env="test",
        cache_enabled=False,
        design_system_viewports=[{"width": 375, "height": 812}],
        design_system_render_wait_ms=50,
        web_vitals_measurement_ms=100,
    )
    guard = LoopbackGuard()
    browser = BrowserManager(settings, guard)  # type: ignore[arg-type]
    try:
        await browser.start()
    except Exception as exc:
        pytest.skip(f"Chromium is unavailable: {exc}")
    try:
        access = await AccessibilityAuditService(browser, guard, settings).audit(fixture_server)  # type: ignore[arg-type]
        assert any(x.issue == "MISSING_ALT" for x in access.issues)
        vitals = await CoreWebVitalsService(browser, guard, settings).measure(fixture_server)  # type: ignore[arg-type]
        assert vitals.viewports
        data, meta = await ScreenshotService(browser, guard, settings).capture(  # type: ignore[arg-type]
            fixture_server, None, 375, 812, False, "png", None, 1.0
        )
        assert data.startswith(b"\x89PNG")
        assert meta.width == 375
        discovery = await APIDiscoveryService(browser, guard, settings).discover(fixture_server)  # type: ignore[arg-type]
        assert any(x.type == "json_api" for x in discovery.endpoints)
        assert any(x.type == "openapi" for x in discovery.endpoints)
    finally:
        await browser.close()
