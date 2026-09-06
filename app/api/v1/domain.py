"""Domain aggregation lookup endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.dependencies import get_domain_service
from app.schemas.domain import DomainLookupRequest, DomainLookupResponse
from app.services.domain_service import DomainService

router = APIRouter(prefix="/domain", tags=["Domain & DNS"])


@router.post(
    "/lookup",
    response_model=DomainLookupResponse,
    summary="Aggregate domain intelligence",
    description=(
        "Combines registration data (RDAP/WHOIS), DNS signals, email-provider "
        "classification and IP-based hosting info. Fields that cannot be "
        "established are returned as null - nothing is fabricated."
    ),
)
async def domain_lookup(
    payload: DomainLookupRequest,
    service: DomainService = Depends(get_domain_service),
) -> DomainLookupResponse:
    data = await service.lookup(payload.domain)
    return DomainLookupResponse(**data)
