"""Password generation endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.dependencies import get_password_service
from app.schemas.password import (
    PasswordGenerateRequest,
    PasswordGenerateResponse,
)
from app.services.password_service import PasswordService

router = APIRouter(prefix="/password", tags=["Validation & Text"])


@router.post(
    "/generate",
    response_model=PasswordGenerateResponse,
    summary="Generate a strong random password",
    description=(
        "Generates a cryptographically secure password using Python's "
        "'secrets' module. At least one character from each enabled category "
        "is guaranteed. Generated passwords are never logged, cached, or "
        "persisted."
    ),
)
async def generate_password(
    payload: PasswordGenerateRequest,
    service: PasswordService = Depends(get_password_service),
) -> PasswordGenerateResponse:
    password = service.generate(payload)
    return PasswordGenerateResponse(random_password=password)
