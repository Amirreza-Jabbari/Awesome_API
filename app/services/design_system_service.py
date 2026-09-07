"""Production-oriented runtime design-system extraction using Playwright/Chromium."""
from __future__ import annotations

import asyncio
import hashlib
import re
import time
from collections import Counter, defaultdict
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from app.core.config import Settings
from app.core.exceptions import (
    BrowserCapacityError,
    ProviderTimeoutError,
    ProviderUnavailableError,
    ResourceLimitError,
    SSRFBlockedError,
)
from app.core.logging import get_logger
from app.providers.web.ssrf import SSRFGuard
from app.schemas.design_system import (
    BreakpointToken,
    ColorToken,
    ComponentInfo,
    ComponentVariant,
    DesignSystemAnalysis,
    DesignSystemResponse,
    DesignSystemTokens,
    Evidence,
    FontToken,
    FrameworkHint,
    IconInfo,
    LayoutInfo,
    SpacingScale,
    WarningItem,
)

EXTRACTOR_VERSION = "1"
logger = get_logger(__name__)
SCHEMA_VERSION = "1"
_COLOR_RE = re.compile(
    r"^(?:#(?:[0-9a-f]{3,4}|[0-9a-f]{6}|[0-9a-f]{8})|(?:rgb|hsl)a?\([^)]*\))$",
    re.I,
)
_NUM_RE = re.compile(r"(-?\d+(?:\.\d+)?)px\b", re.I)

_SAFE_RESOURCE_TYPES = {"document", "stylesheet", "script", "font", "image", "xhr", "fetch"}
_BLOCKED_RESOURCE_TYPES = {"media", "eventsource", "manifest", "texttrack"}

_JS_SNAPSHOT = r"""
({
  maxCandidates: MAX_CANDIDATES,
  maxCssRules: MAX_CSS_RULES,
  maxNodes: MAX_DOM_NODES,
  viewport: { width: window.innerWidth, height: window.innerHeight },
  title: document.title || null,
  htmlLang: document.documentElement.lang || null,
  variables: (() => {
    const out = {};
    const root = document.documentElement;
    for (const name of Array.from(getComputedStyle(root))) {
      if (name.startsWith('--')) {
        const value = getComputedStyle(root).getPropertyValue(name).trim();
        if (value) out[name] = value.slice(0, 512);
      }
    }
    return out;
  })(),
  runtimeStyles: Array.from(document.querySelectorAll('style'))
    .slice(0, MAX_STYLESHEETS)
    .map(s => (s.textContent || '').slice(0, MAX_CSS_TEXT)),
  rules: (() => {
    const rules = [];
    for (const sheet of Array.from(document.styleSheets).slice(0, MAX_STYLESHEETS)) {
      try {
        for (const rule of Array.from(sheet.cssRules).slice(0, MAX_CSS_RULES - rules.length)) {
          if (rule && rule.cssText) rules.push(rule.cssText.slice(0, MAX_CSS_TEXT));
          if (rules.length >= MAX_CSS_RULES) break;
        }
      } catch (_) {}
      if (rules.length >= MAX_CSS_RULES) break;
    }
    return rules;
  })(),
  fonts: (() => {
    const out = [];
    try {
      for (const f of Array.from(document.fonts).slice(0, MAX_FONTS)) {
        out.push({ family: f.family || '', weight: f.weight || 'normal', status: f.status || '' });
      }
    } catch (_) {}
    return out;
  })(),
  fontFaces: Array.from(document.styleSheets).slice(0, MAX_STYLESHEETS).flatMap(sheet => {
    try {
      return Array.from(sheet.cssRules).filter(r => r.type === CSSRule.FONT_FACE_RULE)
        .slice(0, MAX_FONTS).map(r => r.cssText.slice(0, MAX_CSS_TEXT));
    } catch (_) { return []; }
  }),
  elements: (() => {
    const selectors = 'button,a,input,textarea,select,h1,h2,h3,h4,h5,h6,p,nav,header,footer,main,article,section,form,table,[role],[class*="card"],[class*="badge"],[class*="alert"],[class*="tab"]';
    const all = [];
    const nodes = document.getElementsByTagName('*');
    for (let i = 0; i < nodes.length && all.length < MAX_CANDIDATES * 8; i++) {
      const el = nodes[i];
      try { if (el.matches(selectors)) all.push(el); } catch (_) {}
    }
    const seen = new Set();
    const out = [];
    for (const el of all) {
      if (out.length >= MAX_CANDIDATES) break;
      const style = getComputedStyle(el);
      if (style.display === 'none' || style.visibility === 'hidden') continue;
      const rect = el.getBoundingClientRect();
      if (!Number.isFinite(rect.width) || !Number.isFinite(rect.height)) continue;
      const cls = typeof el.className === 'string' ? el.className.split(/\s+/).filter(Boolean).slice(0, 6) : [];
      const signature = [el.tagName.toLowerCase(), cls.join('.'), el.getAttribute('role') || '', style.display, style.fontFamily, style.fontSize, style.fontWeight].join('|');
      if (seen.has(signature) && out.filter(x => x.signature === signature).length >= 4) continue;
      seen.add(signature);
      const props = {};
      for (const p of PROPERTIES) props[p] = style.getPropertyValue(p).trim().slice(0, 256);
      const custom = {};
      for (const p of Array.from(style)) {
        if (p.startsWith('--')) {
          const value = style.getPropertyValue(p).trim();
          if (value) custom[p] = value.slice(0, 256);
        }
      }
      out.push({
        tag: el.tagName.toLowerCase(), role: el.getAttribute('role') || null, cls,
        signature, props, custom,
        rect: { x: Math.round(rect.x), y: Math.round(rect.y), width: Math.round(rect.width), height: Math.round(rect.height) },
        text: (el.textContent || '').trim().slice(0, 120),
        aria: el.getAttribute('aria-label') || null,
        disabled: !!el.disabled,
      });
    }
    return out;
  })(),
  nodeCount: Math.min(document.getElementsByTagName('*').length, MAX_DOM_NODES + 1),
  htmlSize: document.documentElement.outerHTML.length,
  iconSignals: (() => {
    let svg = 0, use = 0, iconClass = 0;
    for (const el of Array.from(document.querySelectorAll('svg,svg use,[class*="icon"],[class*="lucide"],[class*="heroicon"],[class*="material-icons"]')).slice(0, MAX_CANDIDATES)) {
      if (el.tagName.toLowerCase() === 'svg') svg++;
      if (el.tagName.toLowerCase() === 'use') use++;
      if (typeof el.className === 'string' && /icon|lucide|heroicon|material-icons/i.test(el.className)) iconClass++;
    }
    return {svg, use, iconClass};
  })(),
  frameworkSignals: (() => {
    const html = document.documentElement.outerHTML.slice(0, 300000);
    const scripts = Array.from(document.scripts).map(s => s.src || '').join(' ');
    const classes = Array.from(document.querySelectorAll('[class]')).slice(0, MAX_CANDIDATES).map(e => e.className).join(' ');
    return {
      react: !!document.querySelector('[data-reactroot],[data-reactroot=""]') || /__next|_next\/static|react/i.test(html + scripts),
      next: /__next|_next\/static|next\/static/i.test(html + scripts),
      vue: !!document.querySelector('[data-v-app]') || /vue/i.test(scripts),
      nuxt: /__nuxt|_nuxt/i.test(html + scripts),
      angular: !!document.querySelector('[ng-version]') || /ng-version|angular/i.test(html + scripts),
      svelte: /svelte/i.test(html + scripts),
      tailwind: /(?:^|[\s"'])((?:sm|md|lg|xl|2xl):)?(?:flex|grid|space-|gap-|p-|px-|py-|m-|mx-|my-|rounded|text-|bg-|font-)/.test(classes),
      bootstrap: /(?:^|[\s"'])(?:container|row|col-(?:sm|md|lg|xl)|btn|navbar)(?:[\s"']|$)/.test(classes),
      material: /(?:material-icons|mat-mdc-|Mui[A-Z])/i.test(classes + html),
      chakra: /chakra-/i.test(classes),
      ant: /ant-(?:btn|layout|table|menu)|anticon/i.test(classes),
      styledComponents: /data-styled|sc-[a-z0-9]+/i.test(html),
      emotion: /data-emotion|emotion/i.test(html),
      cssModules: /_[a-z0-9]{5,}_[a-z0-9_-]+/i.test(classes),
    };
  })()
})
"""


class BrowserManager:
    """Owns one reusable Chromium process and bounds concurrent contexts."""

    def __init__(self, settings: Settings, guard: SSRFGuard) -> None:
        self._settings = settings
        self._guard = guard
        self._playwright: Any = None
        self._browser: Any = None
        self._sem = asyncio.Semaphore(settings.design_system_max_concurrent_pages)
        self._started = False
        self._start_lock = asyncio.Lock()

    async def start(self) -> None:
        async with self._start_lock:
            if self._started:
                return
            try:
                from playwright.async_api import async_playwright
                self._playwright = await async_playwright().start()
                self._browser = await asyncio.wait_for(
                    self._playwright.chromium.launch(
                        headless=True,
                        chromium_sandbox=True,
                        args=[
                            "--disable-dev-shm-usage",
                            "--disable-background-networking",
                            "--disable-component-update",
                            "--disable-default-apps",
                            "--disable-extensions",
                            "--disable-features=Translate,MediaRouter,OptimizationHints",
                            "--disable-sync",
                            "--no-first-run",
                            "--no-default-browser-check",
                            "--disable-webrtc",
                        ],
                    ),
                    timeout=self._settings.design_system_browser_startup_timeout_ms / 1000,
                )
                self._started = True
            except Exception as exc:
                await self.close()
                raise ProviderUnavailableError("Chromium browser is unavailable.") from exc

    async def close(self) -> None:
        with suppress(Exception):
            if self._browser is not None:
                await self._browser.close()
        self._browser = None
        with suppress(Exception):
            if self._playwright is not None:
                await self._playwright.stop()
        self._playwright = None
        self._started = False

    async def context(self, *, viewport: dict[str, int] | None = None, device_scale_factor: float = 1.0) -> Any:
        if not self._started or self._browser is None:
            await self.start()
        try:
            await asyncio.wait_for(self._sem.acquire(), timeout=self._settings.design_system_queue_timeout_ms / 1000)
        except TimeoutError as exc:
            raise BrowserCapacityError() from exc
        try:
            context = await self._browser.new_context(
                java_script_enabled=True,
                accept_downloads=False,
                service_workers="block",
                ignore_https_errors=False,
                viewport=viewport or self._settings.design_system_viewports[0],
                device_scale_factor=device_scale_factor,
                user_agent=self._settings.webpage_user_agent,
                locale="en-US",
                timezone_id="UTC",
            )
            context.set_default_timeout(self._settings.design_system_browser_timeout_ms)
            context.set_default_navigation_timeout(self._settings.design_system_navigation_timeout_ms)
            return _ManagedContext(context, self._sem, self._guard, self._settings)
        except Exception:
            self._sem.release()
            with suppress(Exception):
                await self.close()
            raise


class _ManagedContext:
    def __init__(self, context: Any, sem: asyncio.Semaphore, guard: SSRFGuard, settings: Settings) -> None:
        self.context = context
        self._sem = sem
        self._guard = guard
        self._settings = settings
        self.request_count = 0
        self.bytes_downloaded = 0
        self.blocked = 0
        self.warnings: list[WarningItem] = []
        self._seen_hosts: set[str] = set()
        self._image_count = 0
        self._lock = asyncio.Lock()

    async def install_network_policy(self) -> None:
        async def handler(route: Any) -> None:
            request = route.request
            url = request.url
            parsed = urlparse(url)
            if parsed.scheme not in {"http", "https"}:
                self.blocked += 1
                await route.abort("blockedbyclient")
                return
            if request.method.upper() not in {"GET", "HEAD"}:
                self.blocked += 1
                await route.abort("blockedbyclient")
                return
            if request.resource_type in _BLOCKED_RESOURCE_TYPES:
                self.blocked += 1
                await route.abort("blockedbyclient")
                return
            if request.resource_type not in _SAFE_RESOURCE_TYPES:
                await route.abort("blockedbyclient")
                self.blocked += 1
                return
            host = parsed.hostname or ""
            redirect_count = 0
            previous = request.redirected_from
            while previous is not None:
                redirect_count += 1
                previous = previous.redirected_from
            if redirect_count > self._settings.design_system_max_redirects:
                self.blocked += 1
                self.warnings.append(WarningItem(code="REDIRECT_LIMIT", message="Navigation exceeded the configured redirect budget."))
                await route.abort("blockedbyclient")
                return
            try:
                addresses = await self._guard.resolve_and_check(host)
                if not addresses:
                    raise SSRFBlockedError("Target address is not allowed.")
            except Exception as exc:
                self.blocked += 1
                self.warnings.append(WarningItem(code="BROWSER_REQUEST_BLOCKED", message="A browser resource was blocked by the network security policy."))
                await route.abort("blockedbyclient")
                if isinstance(exc, ResourceLimitError):
                    raise
                return
            async with self._lock:
                if request.resource_type == "image":
                    self._image_count += 1
                    if self._image_count > self._settings.design_system_max_images:
                        self.blocked += 1
                        await route.abort("blockedbyclient")
                        return
                self.request_count += 1
                if self.request_count > self._settings.design_system_max_requests:
                    self.blocked += 1
                    self.warnings.append(WarningItem(code="REQUEST_LIMIT", message="The browser request budget was reached; additional requests were blocked."))
                    await route.abort("blockedbyclient")
                    return
            try:
                # Fetch one hop only. Redirects are returned to Chromium so each
                # subsequent destination passes through this same SSRF gate.
                response = await route.fetch(
                    max_redirects=0,
                    max_retries=0,
                    timeout=self._settings.design_system_navigation_timeout_ms,
                )
                content_length = response.headers.get("content-length")
                if content_length and int(content_length) > self._settings.design_system_max_response_bytes:
                    self.blocked += 1
                    self.warnings.append(WarningItem(code="RESOURCE_TOO_LARGE", message="A browser resource exceeded the configured size budget."))
                    await route.abort("blockedbyclient")
                    return
                body = await response.body()
                if len(body) > self._settings.design_system_max_response_bytes:
                    self.blocked += 1
                    self.warnings.append(WarningItem(code="RESOURCE_TOO_LARGE", message="A browser resource exceeded the configured size budget."))
                    await route.abort("blockedbyclient")
                    return
                async with self._lock:
                    if self.bytes_downloaded + len(body) > self._settings.design_system_max_total_bytes:
                        self.warnings.append(WarningItem(code="TOTAL_BYTE_LIMIT", message="The aggregate browser resource budget was reached."))
                        await route.abort("blockedbyclient")
                        return
                    self.bytes_downloaded += len(body)
                await route.fulfill(response=response)
            except ResourceLimitError:
                raise
            except Exception:
                self.blocked += 1
                self.warnings.append(WarningItem(code="RESOURCE_FETCH_FAILED", message="A browser resource could not be safely fetched."))
                await route.abort("failed")

        await self.context.route("**/*", handler)

        # Newer Playwright versions expose a dedicated WebSocket router.
        # Use it when available so a naturally-created page WebSocket cannot
        # bypass the SSRF policy. Older versions simply cannot establish a
        # websocket through the HTTP route handler, so no unsafe fallback is
        # introduced here.
        route_websocket = getattr(self.context, "route_web_socket", None)
        if callable(route_websocket):
            async def websocket_handler(ws_route: Any) -> None:
                ws_url = str(getattr(ws_route, "url", ""))
                parsed_ws = urlparse(ws_url)
                if parsed_ws.scheme not in {"ws", "wss"} or not parsed_ws.hostname:
                    self.blocked += 1
                    await ws_route.close(code=1008, reason="blockedbyclient")
                    return
                try:
                    await self._guard.resolve_and_check(parsed_ws.hostname)
                except Exception:
                    self.blocked += 1
                    self.warnings.append(WarningItem(code="BROWSER_WEBSOCKET_BLOCKED", message="A browser WebSocket was blocked by the network security policy."))
                    await ws_route.close(code=1008, reason="blockedbyclient")
                    return
                # Do not inject messages. The target page may establish its
                # own public websocket naturally; discovery only observes it.
                await ws_route.connect_to_server()

            with suppress(Exception):
                await route_websocket("**/*", websocket_handler)

    async def close(self) -> None:
        try:
            await self.context.close()
        finally:
            self._sem.release()


class DesignSystemService:
    def __init__(self, browser: BrowserManager, guard: SSRFGuard, settings: Settings, cache: Any | None = None, metrics: Any | None = None) -> None:
        self._browser = browser
        self._guard = guard
        self._settings = settings
        self._cache = cache
        self._metrics = metrics

    async def extract(self, raw_url: str) -> DesignSystemResponse:
        from app.utils.url import normalize_url

        url = normalize_url(raw_url)
        parsed = urlparse(url)
        await self._guard.resolve_and_check(parsed.hostname or "")
        cache_key = self._cache_key(url)
        if self._cache is not None and self._settings.cache_enabled and self._settings.design_system_cache_ttl > 0:
            cached = await self._cache.get(cache_key)
            if isinstance(cached, dict):
                if self._metrics is not None:
                    self._metrics.observe_cache(True)
                try:
                    return DesignSystemResponse.model_validate(cached)
                except Exception:
                    with suppress(Exception):
                        await self._cache.delete(cache_key)
        if self._metrics is not None:
            self._metrics.observe_cache(False)
        started = time.perf_counter()
        result = await self._extract_uncached(url)
        if self._metrics is not None:
            self._metrics.observe_provider("playwright", "design_system", (time.perf_counter() - started) * 1000, True)
        logger.info("design_system_extraction_complete host=%s partial=%s duration_ms=%s resources=%s", parsed.hostname or "", result.analysis.partial, result.analysis.duration_ms, result.analysis.resources_analyzed)
        if self._cache is not None and self._settings.cache_enabled and self._settings.design_system_cache_ttl > 0:
            with suppress(Exception):
                await self._cache.set(cache_key, result.model_dump(mode="json"), self._settings.design_system_cache_ttl)
        return result

    def _cache_key(self, url: str) -> str:
        normalized = url.split("#", 1)[0]
        digest = hashlib.sha256(normalized.encode()).hexdigest()
        return f"design-system:{EXTRACTOR_VERSION}:{SCHEMA_VERSION}:{digest}"

    async def _extract_uncached(self, url: str) -> DesignSystemResponse:
        started = time.perf_counter()
        managed = await self._browser.context()
        page: Any | None = None
        snapshots: list[dict[str, Any]] = []
        try:
            try:
                page = await managed.context.new_page()
                await managed.install_network_policy()
            except BrowserCapacityError:
                raise
            except Exception as exc:
                raise ProviderUnavailableError("Browser context initialization failed.") from exc
            for index, viewport in enumerate(self._settings.design_system_viewports):
                source_body: bytes | bytearray | None = None
                snapshot: dict[str, Any] | None = None
                if index:
                    await page.set_viewport_size(viewport)
                try:
                    response = await page.goto(url, wait_until="domcontentloaded", timeout=self._settings.design_system_navigation_timeout_ms, referer=None)
                    if response is not None and response.status == 401:
                        from app.core.exceptions import AuthenticationRequiredError
                        raise AuthenticationRequiredError()
                    if response is not None:
                        with suppress(Exception):
                            source_body = await response.body()
                            if len(source_body) > self._settings.design_system_max_response_bytes:
                                managed.warnings.append(WarningItem(code="SOURCE_TOO_LARGE", message="The original HTML response exceeded the configured analysis budget."))
                            else:
                                managed.bytes_downloaded += len(source_body)
                except Exception as exc:
                    if index == 0:
                        if "timeout" in type(exc).__name__.lower():
                            raise ProviderTimeoutError("Website navigation timed out.") from exc
                        raise ProviderUnavailableError("Website navigation failed.") from exc
                    managed.warnings.append(WarningItem(code="VIEWPORT_NAVIGATION_FAILED", message="A responsive viewport could not be fully rendered."))
                    continue
                await page.wait_for_timeout(self._settings.design_system_render_wait_ms)
                try:
                    snapshot = await page.evaluate(
                        _JS_SNAPSHOT.replace("MAX_CANDIDATES", str(self._settings.design_system_max_candidates))
                        .replace("MAX_CSS_RULES", str(self._settings.design_system_max_css_rules))
                        .replace("MAX_DOM_NODES", str(self._settings.design_system_max_dom_nodes))
                        .replace("MAX_STYLESHEETS", str(self._settings.design_system_max_stylesheets))
                        .replace("MAX_FONTS", str(self._settings.design_system_max_fonts))
                        .replace("MAX_CSS_TEXT", str(self._settings.design_system_max_css_text))
                        .replace("PROPERTIES", repr(self._style_properties()).replace("'", '"'))
                    )
                    if isinstance(snapshot, dict):
                        source_text = ""
                        if isinstance(source_body, (bytes, bytearray)) and len(source_body) <= self._settings.design_system_max_response_bytes:
                            source_text = bytes(source_body).decode("utf-8", errors="replace")[:self._settings.design_system_max_response_bytes]
                        snapshot["original_source"] = source_text
                        snapshots.append(snapshot)
                except Exception as exc:
                    if index == 0:
                        raise ProviderUnavailableError("Runtime page analysis failed.") from exc
                    managed.warnings.append(WarningItem(code="VIEWPORT_ANALYSIS_FAILED", message="A responsive viewport could not be analyzed."))
                if snapshot is not None and snapshot.get("nodeCount", 0) > self._settings.design_system_max_dom_nodes:
                    managed.warnings.append(WarningItem(code="DOM_LIMIT_REACHED", message="DOM analysis was bounded by the configured node limit."))
                    break
            if not snapshots:
                raise ProviderUnavailableError("No renderable page state was available.")
            final_url = page.url or url
            tokens = self._normalize(snapshots)
            partial = bool(managed.warnings or managed.blocked)
            if managed.request_count >= self._settings.design_system_max_requests:
                partial = True
                managed.warnings.append(WarningItem(code="REQUEST_BUDGET_REACHED", message="Browser request analysis reached its configured budget."))
            duration_ms = int((time.perf_counter() - started) * 1000)
            result = DesignSystemResponse(
                url=url,
                final_url=final_url,
                fetched_at=datetime.now(UTC),
                extractor_version=EXTRACTOR_VERSION,
                schema_version=SCHEMA_VERSION,
                analysis=DesignSystemAnalysis(
                    duration_ms=duration_ms,
                    viewport_count=len(snapshots),
                    resources_analyzed=managed.request_count,
                    bytes_downloaded=managed.bytes_downloaded,
                    partial=partial,
                ),
                design_system=tokens,
                warnings=managed.warnings,
            )
            return result
        finally:
            with suppress(Exception):
                if page is not None:
                    await page.close()
            await managed.close()

    @staticmethod
    def _style_properties() -> list[str]:
        return [
            "color", "background-color", "border-color", "border-width", "border-style",
            "border-radius", "border-top-left-radius", "border-top-right-radius",
            "border-bottom-right-radius", "border-bottom-left-radius", "box-shadow",
            "font-family", "font-size", "font-weight", "line-height", "letter-spacing",
            "text-transform", "margin", "padding", "padding-top", "padding-right", "padding-bottom", "padding-left",
            "margin-top", "margin-right", "margin-bottom", "margin-left", "gap", "row-gap", "column-gap",
            "width", "height", "max-width", "min-width", "display", "position", "grid-template-columns",
        ]

    def _normalize(self, snapshots: list[dict[str, Any]]) -> DesignSystemTokens:
        colors: Counter[str] = Counter()
        color_sources: defaultdict[str, set[str]] = defaultdict(set)
        color_roles: defaultdict[str, set[str]] = defaultdict(set)
        custom: dict[str, Evidence] = {}
        spacing: Counter[str] = Counter()
        radii: Counter[str] = Counter()
        shadows: Counter[str] = Counter()
        borders: Counter[str] = Counter()
        typography_values: Counter[str] = Counter()
        typography_roles: defaultdict[str, Counter[str]] = defaultdict(Counter)
        widths: Counter[str] = Counter()
        paddings: Counter[str] = Counter()
        gaps: Counter[str] = Counter()
        grid_columns: Counter[str] = Counter()
        components: dict[str, Counter[str]] = defaultdict(Counter)
        component_styles: dict[str, dict[str, dict[str, Counter[str]]]] = defaultdict(
            lambda: defaultdict(lambda: defaultdict(Counter))
        )
        breakpoints: Counter[int] = Counter()
        frameworks: Counter[str] = Counter()
        framework_sources: defaultdict[str, set[str]] = defaultdict(set)
        icon_counts: Counter[str] = Counter()
        fonts: defaultdict[str, set[int]] = defaultdict(set)
        font_sources: defaultdict[str, set[str]] = defaultdict(set)

        for snap in snapshots:
            for name, value in (snap.get("variables") or {}).items():
                value = self._normalize_css_value(str(value))
                if value:
                    custom[name] = Evidence(value=value, confidence=0.99, sources=["css_variable"])
                    if self._is_color(value):
                        c = self._normalize_color(value)
                        colors[c] += 3
                        color_sources[c].add("css_variable")
                        role = self._semantic_role(name)
                        if role:
                            color_roles[c].add(role)
            source_css = str(snap.get("original_source") or "")
            for name, value in re.findall(r"(--[A-Za-z0-9_-]{1,128})\s*:\s*([^;{}]+)", source_css):
                value = self._normalize_css_value(value)
                if value and name not in custom:
                    custom[name] = Evidence(value=value, confidence=0.97, sources=["inline_style", "stylesheet"])
            for css in [source_css] + (snap.get("runtimeStyles") or []) + (snap.get("rules") or []):
                for raw in re.findall(r"(?:^|[;{])\s*([\w-]+)\s*:\s*([^;{}]+)", str(css)):
                    val = raw[1].strip()
                    if self._is_color(val):
                        c = self._normalize_color(val)
                        colors[c] += 1
                        color_sources[c].add("stylesheet" if css == source_css else ("runtime_style" if css in (snap.get("runtimeStyles") or []) else "stylesheet"))
            for el in snap.get("elements") or []:
                for name, value in (el.get("custom") or {}).items():
                    value = self._normalize_css_value(str(value))
                    if value and name not in custom:
                        custom[name] = Evidence(value=value, confidence=0.94, sources=["runtime_computed_style"])
                props = el.get("props") or {}
                tag = str(el.get("tag") or "")
                cls = " ".join(el.get("cls") or [])
                for key in ("color", "background-color", "border-color"):
                    value = props.get(key, "")
                    if self._is_color(value):
                        c = self._normalize_color(value)
                        colors[c] += 1
                        color_sources[c].add("runtime_computed_style")
                        role = self._role_for_element(tag, cls, key)
                        if role:
                            color_roles[c].add(role)
                for key in ("margin", "padding", "gap", "row-gap", "column-gap"):
                    spacing.update(self._extract_px_values(props.get(key, "")))
                for key in ("border-radius", "border-top-left-radius", "border-top-right-radius", "border-bottom-right-radius", "border-bottom-left-radius"):
                    radii.update(self._extract_px_values(props.get(key, "")))
                if props.get("box-shadow") and props["box-shadow"] != "none":
                    shadows[props["box-shadow"]] += 1
                if props.get("border-width") and props.get("border-style", "none") != "none":
                    borders[f"{props.get('border-width')} {props.get('border-style')} {props.get('border-color','')}".strip()] += 1
                font = props.get("font-family", "").strip()
                size = props.get("font-size", "").strip()
                weight = props.get("font-weight", "").strip()
                line = props.get("line-height", "").strip()
                letter = props.get("letter-spacing", "").strip()
                if font or size or weight:
                    sig = "; ".join(x for x in (font, size, weight, line, letter) if x)
                    typography_values[sig] += 1
                    role = self._typography_role(tag, cls)
                    if role:
                        typography_roles[role][sig] += 1
                if props.get("max-width") and props["max-width"] not in {"none", "0px"}:
                    widths[props["max-width"]] += 1
                if props.get("padding-left"):
                    paddings[props["padding-left"]] += 1
                if props.get("gap"):
                    gaps[props["gap"]] += 1
                if props.get("display") == "grid":
                    cols = self._infer_grid_columns(el)
                    if cols:
                        grid_columns[str(cols)] += 1
                name = self._component_name(el)
                if name:
                    variant = self._variant_name(el)
                    components[name][variant] += 1
                    for p in ("background-color", "color", "border-radius", "font-size", "font-weight"):
                        if props.get(p):
                            component_styles[name][variant][p][str(props.get(p))] += 1
            for rule in snap.get("rules") or []:
                for match in re.finditer(r"@media[^({]*\((?:min|max)-width\s*:\s*(\d+)px", str(rule), re.I):
                    breakpoints[int(match.group(1))] += 1
            for fw, present in (snap.get("frameworkSignals") or {}).items():
                if present:
                    frameworks[fw] += 1
                    framework_sources[fw].add("runtime_dom")
            for f in snap.get("fonts") or []:
                family = self._clean_font_family(str(f.get("family") or ""))
                if family:
                    fonts[family].update(self._parse_weight(str(f.get("weight") or "")))
                    font_sources[family].add("runtime")
            for css in snap.get("fontFaces") or []:
                family_match = re.search(r"font-family\s*:\s*[\"']?([^;\"'}]+)", str(css), re.I)
                weight_match = re.search(r"font-weight\s*:\s*([^;]+)", str(css), re.I)
                if family_match:
                    family = self._clean_font_family(family_match.group(1))
                    if family:
                        fonts[family].update(self._parse_weight(weight_match.group(1) if weight_match else ""))
                        font_sources[family].add("font_face")
            signals = snap.get("iconSignals") or {}
            icon_counts["svg"] += int(signals.get("svg", 0))
            icon_counts["svg_use"] += int(signals.get("use", 0))
            icon_counts["icon_class"] += int(signals.get("iconClass", 0))

        color_tokens: dict[str, ColorToken] = {}
        for c, count in colors.most_common(40):
            sources = sorted(color_sources[c])
            confidence = self._confidence(count, direct="runtime_computed_style" in sources or "css_variable" in sources)
            roles = sorted(color_roles[c])
            key = self._color_key(c, roles, len(color_tokens))
            color_tokens[key] = ColorToken(value=c, confidence=confidence, sources=sources, usage_count=count, roles=roles)

        def evidence_counter(counter: Counter[str], limit: int = 20) -> dict[str, Evidence]:
            return {
                self._token_key(v, i): Evidence(
                    value=v,
                    confidence=self._confidence(n),
                    sources=["runtime_computed_style"],
                    usage_count=n,
                )
                for i, (v, n) in enumerate(counter.most_common(limit))
            }

        def evidence_list(counter: Counter[str], limit: int = 20) -> list[Evidence]:
            return [
                Evidence(
                    value=v,
                    confidence=self._confidence(n),
                    sources=["runtime_computed_style"],
                    usage_count=n,
                )
                for v, n in counter.most_common(limit)
            ]

        typography = {}
        for role, counter in typography_roles.items():
            value, count = counter.most_common(1)[0]
            typography[role] = Evidence(value=value, confidence=self._confidence(count, direct=True), sources=["runtime_computed_style"], usage_count=count)
        if not typography and typography_values:
            value, count = typography_values.most_common(1)[0]
            typography["body"] = Evidence(value=value, confidence=self._confidence(count), sources=["runtime_computed_style"], usage_count=count)

        component_info = {}
        for name, counter in list(components.items())[: self._settings.design_system_max_components]:
            total = sum(counter.values())
            variants = []
            for variant, count in counter.most_common(8):
                style = {p: v.most_common(1)[0][0] for p, v in component_styles[name].get(variant, {}).items() if v}
                variants.append(ComponentVariant(variant=variant or "default", occurrences=count, style_signature=style, confidence=self._confidence(count, direct=True)))
            component_info[name] = ComponentInfo(detected=True, occurrences=total, variants=variants, confidence=self._confidence(total, direct=True), sources=["component_pattern", "runtime_computed_style"])

        spacing_values = []
        for v, n in spacing.most_common(20):
            spacing_values.append(Evidence(value=v, confidence=self._confidence(n), sources=["runtime_computed_style"], usage_count=n))
        base = self._infer_base_unit(list(spacing.keys()))
        spacing_conf = 0.8 if base else (0.6 if spacing else 0.0)

        fw_names = {"react": "React", "next": "Next.js", "vue": "Vue", "nuxt": "Nuxt", "angular": "Angular", "svelte": "Svelte", "tailwind": "Tailwind CSS", "bootstrap": "Bootstrap", "material": "Material UI/Material", "chakra": "Chakra UI", "ant": "Ant Design", "styledComponents": "styled-components", "emotion": "Emotion", "cssModules": "CSS Modules"}
        fw = [FrameworkHint(name=fw_names[k], confidence=self._confidence(v, direct=True), sources=sorted(framework_sources[k])) for k, v in frameworks.most_common() if k in fw_names and v >= 1]

        bps = {}
        for width, count in breakpoints.most_common(12):
            bps[f"{width}px"] = BreakpointToken(value=f"{width}px", confidence=self._confidence(count), sources=["media_query"], usage_count=count, viewport_width=width)

        icons = [IconInfo(type=k, confidence=self._confidence(v, direct=True), usage_count=v, sources=["dom_attribute", "component_pattern"]) for k, v in icon_counts.most_common() if v]
        font_models = [FontToken(family=k, weights=sorted(v for v in ws if v), source="runtime" if "runtime" in font_sources[k] else "font_face", confidence=0.96 if "runtime" in font_sources[k] else 0.88) for k, ws in fonts.items()]

        return DesignSystemTokens(
            colors=color_tokens,
            typography=typography,
            spacing=SpacingScale(values=spacing_values, inferred_base_unit=base, confidence=spacing_conf),
            radii=evidence_counter(radii),
            borders=evidence_counter(borders),
            shadows=evidence_counter(shadows),
            breakpoints=bps,
            layout=LayoutInfo(
                container_max_widths=evidence_list(widths),
                horizontal_paddings=evidence_list(paddings),
                common_gaps=evidence_list(gaps),
                grid_columns=evidence_list(grid_columns),
            ),
            components=component_info,
            custom_properties=custom,
            fonts=font_models[:30],
            icons=icons[:10],
            framework_hints=fw[:15],
        )

    @staticmethod
    def _normalize_css_value(value: str) -> str:
        return " ".join(value.strip().split())[:512]

    @staticmethod
    def _is_color(value: str) -> bool:
        return bool(_COLOR_RE.match(value.strip()))

    @staticmethod
    def _normalize_color(value: str) -> str:
        v = value.strip().upper()
        if v.startswith("#"):
            if len(v) in {4, 5}:
                v = "#" + "".join(ch * 2 for ch in v[1:])
            if len(v) == 7:
                return v
            return v
        return v.replace(" ", "")

    @staticmethod
    def _extract_px_values(value: str) -> list[str]:
        return [f"{float(x):g}px" for x in _NUM_RE.findall(value or "") if abs(float(x)) <= 2000]

    @staticmethod
    def _semantic_role(name: str) -> str | None:
        n = name.lower()
        for role in ("primary", "secondary", "accent", "background", "surface", "text", "muted", "border", "success", "warning", "danger", "link"):
            if role in n:
                return role
        return None

    @staticmethod
    def _role_for_element(tag: str, cls: str, prop: str) -> str | None:
        s = f"{tag} {cls}".lower()
        if prop == "background-color":
            for role in ("primary", "secondary", "accent", "success", "warning", "danger"):
                if role in s:
                    return role
            if tag in {"body", "main"}:
                return "background"
            return "surface"
        if prop == "border-color" or "border" in s:
            return "border"
        if prop == "color":
            if tag == "a": return "link"
            if any(x in s for x in ("muted", "secondary", "caption")): return "muted"
            return "text"
        return None

    @staticmethod
    def _typography_role(tag: str, cls: str) -> str | None:
        if tag in {"h1", "h2", "h3", "h4"}: return tag
        if tag == "button": return "button"
        if tag in {"label", "input"}: return "label"
        if tag in {"small"} or "caption" in cls.lower(): return "caption"
        if tag == "p": return "body"
        if "display" in cls.lower(): return "display"
        return None

    @staticmethod
    def _component_name(el: dict[str, Any]) -> str | None:
        tag = str(el.get("tag") or "")
        role = str(el.get("role") or "")
        cls = " ".join(el.get("cls") or []).lower()
        if tag == "button" or role == "button": return "button"
        if tag in {"input", "textarea", "select"}: return "form_control"
        if tag == "nav" or role == "navigation": return "navigation"
        if tag == "form": return "form"
        for name in ("card", "badge", "alert", "tab", "modal", "pagination", "breadcrumb", "avatar", "tooltip", "dropdown", "table"):
            if name in cls or name == role:
                return name
        if tag == "table": return "table"
        return None

    @staticmethod
    def _variant_name(el: dict[str, Any]) -> str:
        cls = " ".join(el.get("cls") or [])
        for word in re.findall(r"[A-Za-z][A-Za-z0-9_-]{1,30}", cls):
            low = word.lower()
            if low in {"primary", "secondary", "success", "warning", "danger", "error", "outline", "ghost", "link", "small", "medium", "large", "sm", "md", "lg", "xl"}:
                return str(low)
        return "default"

    @staticmethod
    def _infer_grid_columns(el: dict[str, Any]) -> int | None:
        value = str((el.get("props") or {}).get("grid-template-columns") or "")
        if not value or value == "none":
            return None
        repeat = re.search(r"repeat\(\s*(\d+)\s*,", value, re.I)
        if repeat:
            return int(repeat.group(1))
        tracks = [part for part in value.split() if part]
        return len(tracks) if 1 < len(tracks) <= 12 else None

    @staticmethod
    def _confidence(count: int, direct: bool = False) -> float:
        if direct:
            return round(min(0.99, 0.82 + min(count, 20) * 0.008), 3)
        return round(min(0.94, 0.58 + min(count, 30) * 0.012), 3)

    @staticmethod
    def _infer_base_unit(values: list[str]) -> float | None:
        nums = []
        for v in values:
            m = re.fullmatch(r"(-?\d+(?:\.\d+)?)px", v)
            if m:
                x = abs(float(m.group(1)))
                if x > 0 and x <= 200:
                    nums.append(x)
        if len(nums) < 3:
            return None
        candidates = [1, 2, 4, 5, 6, 8, 10]
        best = min(candidates, key=lambda u: sum(min(x % u, u - x % u) for x in nums) / len(nums))
        error = sum(min(x % best, best - x % best) for x in nums) / len(nums)
        return float(best) if error <= 0.75 else None

    @staticmethod
    def _token_key(value: str, index: int) -> str:
        return f"value_{index + 1}"

    @staticmethod
    def _color_key(value: str, roles: list[str], index: int) -> str:
        if roles:
            return roles[0] if roles[0] not in {"text", "border", "surface"} else f"{roles[0]}_{index + 1}"
        return f"color_{index + 1}"

    @staticmethod
    def _clean_font_family(value: str) -> str:
        return value.strip().strip("'\"").split(",")[0].strip()

    @staticmethod
    def _parse_weight(value: str) -> set[int]:
        found = set()
        for n in re.findall(r"\b([1-9]\d{2})\b", value):
            i = int(n)
            if 100 <= i <= 900:
                found.add(i)
        if not found and value.strip().lower() == "normal": found.add(400)
        if not found and value.strip().lower() == "bold": found.add(700)
        return found
