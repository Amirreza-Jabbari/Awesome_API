"""DNS lookup endpoint."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from app.core.dependencies import get_dns_service
from app.schemas.dns import DNSLookupRequest, DNSLookupResponse, DNSRecord
from app.services.dns_service import DNSService

router = APIRouter(prefix="/dns", tags=["Domain & DNS"])


@router.post(
    "/lookup",
    response_model=DNSLookupResponse,
    summary="Look up DNS records for a domain",
    description=(
        "Returns A, AAAA, MX, NS, SOA, TXT and CNAME records for a domain. "
        "The optional ``record_types`` field restricts the query. NXDOMAIN and "
        "NODATA are reported as record-type gaps, not as errors."
    ),
)
async def dns_lookup(
    payload: DNSLookupRequest,
    service: DNSService = Depends(get_dns_service),
) -> DNSLookupResponse:
    result = await service.lookup(payload.domain, payload.record_types)
    records = [DNSRecord(**filter_none(item.to_dict())) for item in result.records]
    return DNSLookupResponse(domain=result.domain, records=records)


def filter_none(item: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in item.items() if v is not None}
