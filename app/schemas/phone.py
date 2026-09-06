"""Phone number validation schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field


class PhoneValidateRequest(BaseModel):
    number: str = Field(
        description="Phone number (E.164 recommended, national accepted).",
        min_length=1,
        max_length=32,
    )
    country: str | None = Field(
        default=None,
        description="ISO 3166-1 alpha-2 country code to disambiguate national numbers.",
        max_length=2,
    )


class PhoneValidateResponse(BaseModel):
    is_valid: bool
    is_possible: bool
    is_formatted_properly: bool = False
    country: str | None = None
    country_code: int | None = None
    location: str | None = None
    timezones: list[str] = Field(default_factory=list)
    format_national: str | None = None
    format_international: str | None = None
    format_e164: str | None = None
    format_rfc3966: str | None = None
    line_type: str | None = None
    is_mobile: bool | None = None
    reason: str | None = None
