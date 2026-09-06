"""DNS lookup schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from app.core.exceptions import InvalidDomainError
from app.utils.domain import normalize_domain

RecordTypes = ("A", "AAAA", "MX", "NS", "SOA", "TXT", "CNAME")


class DNSLookupRequest(BaseModel):
    domain: str = Field(description="The domain to look up.", min_length=1, max_length=255)
    record_types: list[str] | None = Field(
        default=None,
        description="Optional subset of record types. Defaults to all supported types.",
    )

    @field_validator("domain")
    @classmethod
    def _normalize_domain(cls, v: str) -> str:
        try:
            return normalize_domain(v)
        except InvalidDomainError as exc:
            raise ValueError(exc.message) from exc

    @field_validator("record_types")
    @classmethod
    def _validate_record_types(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        cleaned = [t.upper().strip() for t in v if t.strip()]
        invalid = [t for t in cleaned if t not in RecordTypes]
        if invalid:
            raise ValueError(f"Unsupported record type(s): {', '.join(invalid)}")
        if not cleaned:
            raise ValueError("record_types must not be empty")
        return cleaned


class DNSARecord(BaseModel):
    record_type: str = "A"
    value: str
    ttl: int | None = None


class DNSAAAARecord(BaseModel):
    record_type: str = "AAAA"
    value: str
    ttl: int | None = None


class DNSMXRecord(BaseModel):
    record_type: str = "MX"
    priority: int
    value: str
    ttl: int | None = None


class DNSNSRecord(BaseModel):
    record_type: str = "NS"
    value: str
    ttl: int | None = None


class DNSSOARecord(BaseModel):
    record_type: str = "SOA"
    mname: str
    rname: str
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int
    ttl: int | None = None


class DNSTXTRecord(BaseModel):
    record_type: str = "TXT"
    value: str
    ttl: int | None = None


class DNSCNAMERecord(BaseModel):
    record_type: str = "CNAME"
    value: str
    ttl: int | None = None


class DNSRecord(BaseModel):
    record_type: str
    value: str | None = None
    priority: int | None = None
    ttl: int | None = None
    mname: str | None = None
    rname: str | None = None
    serial: int | None = None
    refresh: int | None = None
    retry: int | None = None
    expire: int | None = None
    minimum: int | None = None


class DNSLookupResponse(BaseModel):
    domain: str
    records: list[DNSRecord]
