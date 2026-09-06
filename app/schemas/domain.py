"""Domain aggregation lookup schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from app.core.exceptions import InvalidDomainError
from app.utils.domain import normalize_domain


class DomainLookupRequest(BaseModel):
    domain: str = Field(description="The domain to analyse.", min_length=1, max_length=255)

    @field_validator("domain")
    @classmethod
    def _normalize_domain(cls, v: str) -> str:
        try:
            return normalize_domain(v)
        except InvalidDomainError as exc:
            raise ValueError(exc.message) from exc


class DomainLookupResponse(BaseModel):
    domain: str
    available: bool | None = Field(
        default=None,
        description=(
            "True when the registry explicitly reports the domain is "
            "unregistered, false when a registration record exists, null when "
            "the registry data is unavailable."
        ),
    )
    creation_date: int | None = None
    expiration_date: int | None = None
    updated_date: int | None = None
    registrar: str | None = None
    domain_status: list[str] = Field(default_factory=list)
    age_days: int | None = None
    has_mx: bool | None = None
    is_free_email_provider: bool | None = None
    risky_tld: bool | None = None
    is_disposable_email_domain: bool | None = None
    is_malicious: bool | None = Field(
        default=None,
        description=(
            "True when the host (or one of its subdomains) appears on the "
            "maintained malicious/abusive hosts blocklist. Exact and suffix "
            "matching is applied. Heuristic signal for classification, never "
            "actionable policy."
        ),
    )
    mx_provider: str | None = None
    is_parked: bool | None = None
    ip: str | None = None
    hosting_provider: str | None = None
    country: str | None = None
    is_custom_domain: bool | None = None
