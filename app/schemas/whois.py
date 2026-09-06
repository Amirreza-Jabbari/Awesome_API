"""WHOIS/RDAP lookup schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from app.core.exceptions import InvalidDomainError
from app.utils.domain import normalize_domain


class WhoIsLookupRequest(BaseModel):
    domain: str = Field(
        description="Domain to query registration data for.",
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


class WhoIsLookupResponse(BaseModel):
    domain_name: str | None = None
    registrar: str | None = None
    registrar_url: str | None = None
    whois_server: str | None = None
    updated_date: int | None = Field(default=None, description="Unix timestamp (seconds).")
    creation_date: int | None = Field(default=None, description="Unix timestamp (seconds).")
    expiration_date: int | None = Field(default=None, description="Unix timestamp (seconds).")
    name_servers: list[str] = Field(default_factory=list)
    dnssec: str | None = None
    status: list[str] = Field(default_factory=list)
    source: str | None = Field(description="provider used: rdap or whois")
