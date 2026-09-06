"""Cron endpoints: schedule generation and cron expression parsing."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from app.core.dependencies import get_cron_service
from app.schemas.cron_tools import (
    CronGenerateRequest,
    CronGenerateResponse,
    CronParseRequest,
    CronParseResponse,
)
from app.services.cron_service import CronService

router = APIRouter()


# ── Cron Generator ───────────────────────────────────────────────────────────

@router.post(
    "/cron/generate",
    response_model=CronGenerateResponse,
    tags=["Time & Date"],
    summary="Generate a cron expression from plain English",
    description=(
        "Converts natural-language schedule descriptions such as 'every 30 "
        "minutes', 'every weekday at 09:30' or 'on january 1, 2027 at 09:00' "
        "into a standard 5-field cron expression with a human-readable "
        "description and per-field breakdown."
    ),
)
async def cron_generate(
    payload: CronGenerateRequest,
    service: CronService = Depends(get_cron_service),
) -> dict[str, Any]:
    return service.generate(payload.schedule)


# ── Cron Parser ──────────────────────────────────────────────────────────────

@router.post(
    "/cron/parse",
    response_model=CronParseResponse,
    tags=["Time & Date"],
    summary="Validate and expand a cron expression",
    description=(
        "Validates a 5-field cron expression, expands every field into its "
        "allowed values (supporting *, ranges, steps, lists and weekday/month "
        "names) and computes the next N scheduled times in UTC relative to an "
        "optional reference timestamp."
    ),
)
async def cron_parse(
    payload: CronParseRequest,
    service: CronService = Depends(get_cron_service),
) -> dict[str, Any]:
    return service.parse(
        payload.expression, payload.count, payload.reference_timestamp,
    )
