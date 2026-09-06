"""Webpage metadata extraction schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from app.core.exceptions import InvalidURLError
from app.utils.url import normalize_url


class WebpageLookupRequest(BaseModel):
    url: str = Field(
        description="URL of the webpage to extract metadata from.",
        min_length=1,
        max_length=2048,
    )

    @field_validator("url")
    @classmethod
    def _normalize_url(cls, v: str) -> str:
        try:
            return normalize_url(v)
        except InvalidURLError as exc:
            raise ValueError(exc.message) from exc


class WebpageLookupResponse(BaseModel):
    url: str = Field(description="The final URL after any redirects.")
    domain: str
    url_path: str
    url_parameters: dict[str, str] = Field(default_factory=dict)
    page_title: str | None = None
    page_description: str | None = None
    meta_tags: dict[str, str] = Field(default_factory=dict)
    favicon: str | None = None
    final_url: str | None = None
    fetched_domain: str | None = None
