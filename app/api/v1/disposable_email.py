"""Disposable email checker endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.dependencies import get_disposable_email_service
from app.schemas.disposable_email import (
    DisposableEmailRequest,
    DisposableEmailResponse,
)
from app.services.disposable_email_service import DisposableEmailService

router = APIRouter(prefix="/email", tags=["Email"])


@router.post(
    "/disposable-check",
    response_model=DisposableEmailResponse,
    summary="Check if an email domain is disposable",
    description=(
        "Returns whether the email's domain is a known disposable-email "
        "provider. Subdomains of listed disposable hosts count as disposable. "
        "IDN domains and case are normalized."
    ),
)
async def check_disposable_email(
    payload: DisposableEmailRequest,
    service: DisposableEmailService = Depends(get_disposable_email_service),
) -> DisposableEmailResponse:
    result = service.check(payload.email)
    return DisposableEmailResponse(
        email=result.email, domain=result.domain, is_disposable=result.is_disposable
    )
