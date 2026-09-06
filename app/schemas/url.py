"""URL lookup schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from app.core.exceptions import InvalidURLError
from app.utils.url import normalize_url


class URLLookupRequest(BaseModel):
    url: str = Field(description="URL or bare hostname to analyse.", min_length=1, max_length=2048)

    @field_validator("url")
    @classmethod
    def _normalize_url(cls, v: str) -> str:
        try:
            return normalize_url(v)
        except InvalidURLError as exc:
            raise ValueError(exc.message) from exc


class URLLookupResponse(BaseModel):
    url: str
    is_valid: bool = True
    country: str | None = None
    country_code: str | None = None
    region: str | None = None
    region_code: str | None = None
    city: str | None = None
    zip: str | None = None
    lat: float | None = None
    lon: float | None = None
    timezone: str | None = None
    isp: str | None = None
    ip: str | None = None
