"""Webpage metadata extraction endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.dependencies import get_webpage_service
from app.schemas.webpage import (
    WebpageLookupRequest,
    WebpageLookupResponse,
)
from app.services.webpage_service import WebpageService

router = APIRouter(prefix="/webpage", tags=["Web Analysis"])


@router.post(
    "/lookup",
    response_model=WebpageLookupResponse,
    summary="Extract webpage metadata",
    description=(
        "Fetches an HTML page (with strict SSRF protection, size/timeout "
        "limits, and redirect validation) and extracts title, description, "
        "meta tags and favicon. JavaScript is never executed."
    ),
)
async def webpage_lookup(
    payload: WebpageLookupRequest,
    service: WebpageService = Depends(get_webpage_service),
) -> WebpageLookupResponse:
    data = await service.extract(payload.url)
    return WebpageLookupResponse(**data)
