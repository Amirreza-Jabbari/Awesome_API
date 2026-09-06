"""IP lookup endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.dependencies import get_ip_service
from app.schemas.ip import IPLookupRequest, IPLookupResponse
from app.services.ip_service import IPService

router = APIRouter(prefix="/ip", tags=["IP & Network"])


@router.post(
    "/lookup",
    response_model=IPLookupResponse,
    summary="IP address intelligence",
    description=(
        "Validates and classifies an IPv4/IPv6 address locally, then queries "
        "the configured GeoIP/intelligence providers for additional data. "
        "Private and reserved addresses are never sent to external providers; "
        "unknown signals are returned as null."
    ),
)
async def ip_lookup(
    payload: IPLookupRequest,
    service: IPService = Depends(get_ip_service),
) -> IPLookupResponse:
    data = await service.lookup(payload.ip)
    return IPLookupResponse(**data)
