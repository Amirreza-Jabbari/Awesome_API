"""Phone validation endpoint."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from app.core.dependencies import get_phone_service
from app.schemas.phone import PhoneValidateRequest, PhoneValidateResponse
from app.services.phone_service import PhoneValidationService

router = APIRouter(prefix="/phone", tags=["Validation & Text"])


@router.post(
    "/validate",
    response_model=PhoneValidateResponse,
    summary="Validate a phone number",
    description=(
        "Validates and formats a phone number using libphonenumber. Distinguishes "
        "'possible' from 'valid'. Validation follows numbering-plan rules and does "
        "NOT assert the number is currently assigned or reachable."
    ),
)
async def phone_validate(
    payload: PhoneValidateRequest,
    service: PhoneValidationService = Depends(get_phone_service),
) -> PhoneValidateResponse:
    result = service.validate(payload.number, payload.country)
    data: dict[str, Any] = {
        "is_valid": result.is_valid,
        "is_possible": result.is_possible,
        "is_formatted_properly": result.is_formatted_properly,
        "country": result.country,
        "country_code": result.country_code,
        "location": result.location,
        "timezones": result.timezones or [],
        "format_national": result.format_national,
        "format_international": result.format_international,
        "format_e164": result.format_e164,
        "format_rfc3966": result.format_rfc3966,
        "line_type": result.line_type,
        "is_mobile": result.is_mobile,
        "reason": result.reason,
    }
    return PhoneValidateResponse(**data)
