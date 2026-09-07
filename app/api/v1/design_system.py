"""Runtime Design System Extractor endpoint."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.core.dependencies import get_design_system_service
from app.schemas.design_system import DesignSystemResponse
from app.services.design_system_service import DesignSystemService

router = APIRouter(prefix="/web", tags=["Web Analysis"])


@router.get(
    "/design-system",
    response_model=DesignSystemResponse,
    summary="Extract a rendered website design system",
    description=(
        "Renders a public HTTP(S) page in an isolated Chromium context through Playwright, "
        "then infers normalized design tokens from source CSS, runtime styles, computed CSS, "
        "DOM patterns and bounded responsive viewport analysis. Public pages only; authentication "
        "and generic UI actions are not supported. Browser requests are subject to "
        "SSRF and resource policies."
    ),
    responses={
        422: {"description": "Invalid URL or SSRF/security policy rejection."},
        502: {"description": "The target or Chromium browser could not be reached."},
        503: {"description": "The browser service is unavailable."},
        504: {"description": "Browser navigation exceeded the configured timeout."},
    },
)
async def design_system(
    url: str = Query(..., min_length=1, max_length=2048, description="Public HTTP(S) website URL."),
    service: DesignSystemService = Depends(get_design_system_service),
) -> DesignSystemResponse:
    return await service.extract(url)
