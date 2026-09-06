"""MX lookup schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from app.core.exceptions import InvalidDomainError
from app.utils.domain import normalize_domain


class MXLookupRequest(BaseModel):
    domain: str = Field(
        description="The domain to query for MX records.",
        min_length=1,
        max_length=255,
    )

    @field_validator("domain")
    @classmethod
    def _normalize_domain(cls, v: str) -> str:
        try:
            return normalize_domain(v)
        except InvalidDomainError as exc:
            raise ValueError(exc.message) from exc


class MXRecord(BaseModel):
    priority: int = Field(description="MX preference value (lower = higher priority).")
    value: str = Field(description="Mail exchange hostname.")


class MXLookupResponse(BaseModel):
    domain: str
    records: list[MXRecord]
    has_mx: bool
