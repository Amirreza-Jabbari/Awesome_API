"""User-Agent parser schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field


class UserAgentParseRequest(BaseModel):
    useragent: str = Field(description="The raw User-Agent header string.", max_length=2048)


class UserAgentParseResponse(BaseModel):
    browser_family: str | None = Field(default=None, description="Browser product family.")
    browser_version: str | None = None
    os_family: str | None = None
    os_version: str | None = None
    device_family: str | None = None
    device_brand: str | None = None
    device_model: str | None = None
    device_type: str | None = None
    is_valid: bool = Field(description="Whether the string is a valid UA string.")
    invalid_reason: str | None = Field(description="Why the string is invalid, if it is.")
