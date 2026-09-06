"""URL lookup endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.dependencies import get_url_service
from app.schemas.url import URLLookupRequest, URLLookupResponse
from app.services.url_service import URLService

router = APIRouter(prefix="/url", tags=["IP & Network"])


@router.post(
    "/lookup",
    response_model=URLLookupResponse,
    summary="URL / hostname intelligence",
    description=(
        "Parses, validates and resolves a URL (schemeless URLs are accepted) "
        "and returns IP/geolocation data for its host. This endpoint does not "
        "fetch the URL's content and cannot be abused as an HTTP proxy."
    ),
)
async def url_lookup(
    payload: URLLookupRequest,
    service: URLService = Depends(get_url_service),
) -> URLLookupResponse:
    data = await service.lookup(payload.url)
    return URLLookupResponse(**data)
