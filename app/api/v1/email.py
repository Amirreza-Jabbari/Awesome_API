"""Email validation endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.dependencies import get_email_service
from app.schemas.email import EmailValidateRequest, EmailValidateResponse
from app.services.email_service import EmailValidationService

router = APIRouter(prefix="/email", tags=["Email"])


@router.post(
    "/validate",
    response_model=EmailValidateResponse,
    summary="Validate an email address",
    description=(
        "Validates email syntax, normalizes the domain (IDN-aware), and reports "
        "disposable/free-provider status, MX existence and a coarse category "
        "(disposable/public_email/business) derived from local host lists only. "
        "'is_valid' refers to syntax only; mailbox existence is NOT verified."
    ),
)
async def email_validate(
    payload: EmailValidateRequest,
    service: EmailValidationService = Depends(get_email_service),
) -> EmailValidateResponse:
    data = await service.validate(payload.email)
    return EmailValidateResponse(**data)
