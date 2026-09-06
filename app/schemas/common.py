"""Common schemas shared across endpoints: error envelope and generic types."""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, Field


class ErrorDetail(BaseModel):
    code: str = Field(description="Machine-readable error code.")
    message: str = Field(description="Human-readable error message.")
    details: dict[str, object] | None = Field(
        default=None, description="Optional safe, non-sensitive error metadata."
    )
    request_id: str = Field(description="Request correlation identifier.")


class ErrorResponse(BaseModel):
    error: ErrorDetail


class HealthResponse(BaseModel):
    status: str = Field(description="One of: healthy, ready, degraded.")
    version: str
    checks: dict[str, str] = Field(default_factory=dict)


class ReadyResponse(BaseModel):
    status: str
    readiness: dict[str, bool] = Field(default_factory=dict)


class VersionResponse(BaseModel):
    name: str
    version: str
    environment: str


DomainStr = Annotated[
    str,
    Field(
        description="A domain name, IDNs accepted, whitespace/case normalized.",
        min_length=1,
        max_length=255,
    ),
]

IPStr = Annotated[
    str,
    Field(description="An IPv4 or IPv6 address.", min_length=1, max_length=45),
]
