"""Schemas for cron expression generation and parsing."""
from __future__ import annotations

from pydantic import BaseModel, Field


class CronGenerateRequest(BaseModel):
    schedule: str = Field(min_length=1, max_length=300)


class CronGenerateResponse(BaseModel):
    valid: bool
    error: str | None = None
    expression: str | None = None
    description: str | None = None
    fields: dict[str, CronFieldDetail] | None = None


class CronFieldDetail(BaseModel):
    value: str
    values: list[int] = Field(default_factory=list)
    valid: bool = True
    error: str | None = None


class CronParseRequest(BaseModel):
    expression: str = Field(min_length=1, max_length=300)
    count: int = Field(default=10, ge=1, le=100)
    reference_timestamp: float | None = None


class CronParseResponse(BaseModel):
    valid: bool
    error: str | None = None
    fields: dict[str, CronFieldDetail] | None = None
    next_count: int = 0
    next_times: list[str] = Field(default_factory=list)
