"""Browser-based web intelligence endpoints."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Query, Response

from app.core.dependencies import (
    get_accessibility_audit_service,
    get_api_discovery_service,
    get_core_web_vitals_service,
    get_screenshot_service,
)
from app.schemas.browser_intelligence import (
    AccessibilityResponse,
    DiscoveryResponse,
    WebVitalsResponse,
)
from app.services.browser_intelligence_service import (
    APIDiscoveryService,
    AccessibilityAuditService,
    CoreWebVitalsService,
    ScreenshotService,
)

router = APIRouter(prefix="/web", tags=["Web Analysis"])


@router.get(
    "/accessibility-audit",
    response_model=AccessibilityResponse,
    summary="Audit rendered accessibility",
    description="Automated heuristic accessibility analysis of a public, browser-rendered page. "
    "Checks common WCAG-related image, ARIA, keyboard, form, heading, landmark, metadata, "
    "and computed text-contrast conditions. It is not a WCAG certification tool.",
)
async def accessibility_audit(
    url: str = Query(..., min_length=1, max_length=2048),
    service: AccessibilityAuditService = Depends(get_accessibility_audit_service),
) -> AccessibilityResponse:
    return await service.audit(url)


@router.get(
    "/core-web-vitals",
    response_model=WebVitalsResponse,
    summary="Estimate Core Web Vitals in Chromium",
    description="Synthetic browser measurement of FCP, LCP, CLS and supported interaction timing. "
    "Results are estimates from the current Chromium session and are not CrUX, RUM, or PageSpeed data.",
)
async def core_web_vitals(
    url: str = Query(..., min_length=1, max_length=2048),
    service: CoreWebVitalsService = Depends(get_core_web_vitals_service),
) -> WebVitalsResponse:
    return await service.measure(url)


@router.get(
    "/screenshot",
    summary="Capture a rendered website screenshot",
    description="Render a public HTTP(S) URL in isolated Chromium and return a bounded image. "
    "The target and every browser resource are subject to SSRF and resource policies.",
)
async def screenshot(
    url: str = Query(..., min_length=1, max_length=2048),
    selector: str | None = Query(default=None, max_length=512),
    width: int | None = Query(default=None, ge=1),
    height: int | None = Query(default=None, ge=1),
    full_page: bool = Query(default=False),
    format: Literal["png", "jpeg", "webp"] = Query(default="png"),
    quality: int | None = Query(default=None, ge=1, le=100),
    device_scale_factor: float = Query(default=1.0, ge=1.0, le=2.0),
    service: ScreenshotService = Depends(get_screenshot_service),
) -> Response:
    data, meta = await service.capture(
        url, selector, width, height, full_page, format, quality, device_scale_factor
    )
    media = "image/jpeg" if format == "jpeg" else f"image/{format}"
    return Response(
        content=data,
        media_type=media,
        headers={
            "Content-Length": str(len(data)),
            "X-Screenshot-Final-URL": str(meta.final_url),
            "X-Screenshot-Width": str(meta.width),
            "X-Screenshot-Height": str(meta.height),
        },
    )


@router.get(
    "/api-discovery",
    response_model=DiscoveryResponse,
    summary="Discover public API endpoints observed by Chromium",
    description="Passive, bounded discovery of public API documentation and browser-observed endpoints. "
    "This is not a vulnerability scanner, port scanner, brute-force crawler, or exploitation tool.",
)
async def api_discovery(
    url: str = Query(..., min_length=1, max_length=2048),
    service: APIDiscoveryService = Depends(get_api_discovery_service),
) -> DiscoveryResponse:
    return await service.discover(url)
