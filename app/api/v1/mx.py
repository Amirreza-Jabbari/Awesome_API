"""MX lookup endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.dependencies import get_mx_service
from app.schemas.mx import MXLookupRequest, MXLookupResponse, MXRecord
from app.services.mx_service import MXService

router = APIRouter(prefix="/mx", tags=["Domain & DNS"])


@router.post(
    "/lookup",
    response_model=MXLookupResponse,
    summary="Look up MX records for a domain",
    description=(
        "Returns the mail-exchange records for a domain, sorted by priority "
        "ascending. A domain without MX records returns ``has_mx: false``."
    ),
)
async def mx_lookup(
    payload: MXLookupRequest,
    service: MXService = Depends(get_mx_service),
) -> MXLookupResponse:
    domain, hosts = await service.lookup(payload.domain)
    if not hosts:
        return MXLookupResponse(domain=domain, records=[], has_mx=False)
    records = [MXRecord(priority=h.priority, value=h.hostname) for h in hosts]
    return MXLookupResponse(domain=domain, records=records, has_mx=True)
