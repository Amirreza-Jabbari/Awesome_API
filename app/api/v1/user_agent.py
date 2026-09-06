"""User-Agent parsing endpoint."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from app.core.dependencies import get_user_agent_service
from app.schemas.user_agent import (
    UserAgentParseRequest,
    UserAgentParseResponse,
)
from app.services.user_agent_service import UserAgentService

router = APIRouter(prefix="/user-agent", tags=["Web Analysis"])


@router.post(
    "/parse",
    response_model=UserAgentParseResponse,
    summary="Parse a User-Agent header",
    description=(
        "Parses a user-agent string into browser, OS and device attributes. "
        "'valid but unknown' is distinguished from 'malformed'."
    ),
)
async def parse_user_agent(
    payload: UserAgentParseRequest,
    service: UserAgentService = Depends(get_user_agent_service),
) -> UserAgentParseResponse:
    result = service.parse(payload.useragent)
    data: dict[str, Any] = {
        "browser_family": result.browser_family,
        "browser_version": result.browser_version,
        "os_family": result.os_family,
        "os_version": result.os_version,
        "device_family": result.device_family,
        "device_brand": result.device_brand,
        "device_model": result.device_model,
        "device_type": result.device_type,
        "is_valid": result.is_valid,
        "invalid_reason": result.invalid_reason,
    }
    return UserAgentParseResponse(**data)
