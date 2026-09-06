"""WHOIS/RDAP lookup endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.dependencies import get_whois_service
from app.schemas.whois import WhoIsLookupRequest, WhoIsLookupResponse
from app.services.whois_service import WhoIsService

router = APIRouter(prefix="/whois", tags=["Domain & DNS"])


@router.post(
    "/lookup",
    response_model=WhoIsLookupResponse,
    summary="Look up WHOIS/RDAP registration data",
    description=(
        "Returns registration data using RDAP when the registry supports it, "
        "falling back to WHOIS. Dates are returned as Unix timestamps. "
        "Privacy-protected or missing fields are returned as null."
    ),
)
async def whois_lookup(
    payload: WhoIsLookupRequest,
    service: WhoIsService = Depends(get_whois_service),
) -> WhoIsLookupResponse:
    record = await service.lookup(payload.domain)
    return WhoIsLookupResponse(**WhoIsService.record_to_dict(record))
