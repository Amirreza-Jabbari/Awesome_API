"""Schemas for local developer/security utilities."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from app.core.limits import validate_json_structure


class JWTInspectRequest(BaseModel):
    token: str = Field(min_length=10, max_length=16384)

class JWTInspectResponse(BaseModel):
    is_valid: bool
    header: dict[str, object] | None = None
    payload: dict[str, object] | None = None
    signature_present: bool = False
    algorithm: str | None = None
    token_type: str | None = None
    issuer: str | None = None
    audience: str | list[str] | None = None
    subject: str | None = None
    issued_at: int | None = None
    expires_at: int | None = None
    not_before: int | None = None
    is_expired: bool | None = None
    error: str | None = None

class JWTGenerateRequest(BaseModel):
    payload: dict[str, object] = Field(default_factory=dict, max_length=200)
    algorithm: Literal["HS256", "HS384", "HS512"] = "HS256"
    secret: str = Field(min_length=32, max_length=4096)
    expires_in: int = Field(default=3600, ge=1, le=31536000)
    issuer: str | None = Field(default=None, max_length=1024)
    subject: str | None = Field(default=None, max_length=1024)
    audience: str | list[str] | None = None
    token_id: str | None = Field(default=None, max_length=1024)
    headers: dict[str, str] = Field(default_factory=dict, max_length=20)

    @field_validator("secret")
    @classmethod
    def _validate_secret_entropy(cls, value: str) -> str:
        if len(value.encode("utf-8")) < 32:
            raise ValueError("JWT secret must contain at least 256 bits of UTF-8 key material.")
        return value

    @model_validator(mode="after")
    def _validate_payload_structure(self) -> JWTGenerateRequest:
        validate_json_structure(self.payload, max_depth=20, max_nodes=1000)
        return self

class JWTGenerateResponse(BaseModel):
    token: str
    token_type: str = "JWT"
    algorithm: str
    header: dict[str, object] = Field(default_factory=dict)
    payload: dict[str, object] = Field(default_factory=dict)
    issued_at: int
    expires_at: int
    expires_in: int

class HashGenerateRequest(BaseModel):
    input: str = Field(max_length=4_000_000)
    algorithm: Literal[
        "md5", "sha1", "sha224", "sha256", "sha384", "sha512", "blake2b", "blake2s"
    ] = "sha256"
    encoding: Literal["utf-8", "base64", "hex"] = "utf-8"

class HashGenerateResponse(BaseModel):
    algorithm: str
    digest_hex: str
    digest_base64: str
    input_encoding: str

class HashIdentifyRequest(BaseModel):
    hash: str = Field(min_length=1, max_length=1024)

class HashCandidate(BaseModel):
    algorithm: str
    confidence: Literal["high", "medium", "low"]
    reason: str

class HashIdentifyResponse(BaseModel):
    normalized: str
    length: int
    candidates: list[HashCandidate]
    note: str

class CodecRequest(BaseModel):
    value: str = Field(max_length=4_000_000)
    mode: Literal["encode", "decode"]
    encoding: Literal["utf-8", "hex"] = "utf-8"

class CodecResponse(BaseModel):
    value: str
    encoding: str

class URLCodecRequest(BaseModel):
    value: str = Field(max_length=4_000_000)
    mode: Literal["encode", "decode"]
    component: bool = True

class URLCodecResponse(BaseModel):
    value: str
    mode: str

class HTMLCodecRequest(BaseModel):
    value: str = Field(max_length=4_000_000)
    mode: Literal["encode", "decode"]
    quote: bool = True

class HTMLCodecResponse(BaseModel):
    value: str
    mode: str

class UUIDRequest(BaseModel):
    version: Literal[1, 3, 4, 5, 7] = 4
    namespace: str | None = None
    name: str | None = None

    @model_validator(mode="after")
    def validate_namespace(self) -> UUIDRequest:
        if self.version in (3, 5) and (not self.namespace or self.name is None):
            raise ValueError("UUID versions 3 and 5 require namespace and name.")
        return self

class UUIDResponse(BaseModel):
    uuid: str
    version: int
    variant: str
    is_valid: bool = True

class UUIDValidateRequest(BaseModel):
    uuid: str = Field(min_length=1, max_length=64)

class ULIDRequest(BaseModel):
    count: int = Field(default=1, ge=1, le=100)

class ULIDResponse(BaseModel):
    ulids: list[str]

class ULIDValidateRequest(BaseModel):
    ulid: str = Field(min_length=26, max_length=26)

class ULIDValidationResponse(BaseModel):
    ulid: str
    is_valid: bool
    timestamp_ms: int | None = None
    datetime_utc: str | None = None
    error: str | None = None

class TimestampRequest(BaseModel):
    timestamp: float | None = None
    datetime: str | None = None
    timezone: str = "UTC"

    @model_validator(mode="after")
    def exactly_one_input(self) -> TimestampRequest:
        if (self.timestamp is None) == (self.datetime is None):
            raise ValueError("Provide exactly one of timestamp or datetime.")
        return self

class TimestampResponse(BaseModel):
    unix_seconds: float
    unix_milliseconds: int
    utc: str
    local: str
    timezone: str
    iso8601: str

class TimezoneRequest(BaseModel):
    ip: str | None = None
    latitude: float | None = Field(default=None, ge=-90, le=90)
    longitude: float | None = Field(default=None, ge=-180, le=180)

    @model_validator(mode="after")
    def validate_target(self) -> TimezoneRequest:
        if self.ip and (self.latitude is not None or self.longitude is not None):
            raise ValueError("Provide either ip or coordinates, not both.")
        if self.ip is None and (self.latitude is None or self.longitude is None):
            raise ValueError("Provide an IP address or both latitude and longitude.")
        return self

class TimezoneResponse(BaseModel):
    timezone: str | None
    source: str
    country: str | None = None
    country_code: str | None = None
    latitude: float | None = None
    longitude: float | None = None

class HTTPHeadersRequest(BaseModel):
    headers: dict[str, str] = Field(default_factory=dict, max_length=200)

class HTTPHeadersResponse(BaseModel):
    headers: dict[str, str]
    security: dict[str, str | bool | int | None]
    caching: dict[str, str | bool | None]
    cors: dict[str, str | bool | None]
    server: dict[str, str | bool | None]
    content: dict[str, str | bool | None]

class LiveURLRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)

class SecurityHeadersResponse(BaseModel):
    url: str
    status_code: int
    headers: dict[str, str]
    score: int
    checks: list[dict[str, object]]

class TLSLookupRequest(BaseModel):
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(default=443, ge=1, le=65535)

class TLSLookupResponse(BaseModel):
    host: str
    port: int
    verified: bool
    subject: dict[str, str] = Field(default_factory=dict)
    issuer: dict[str, str] = Field(default_factory=dict)
    serial_number: str | None = None
    version: int | None = None
    not_before: str | None = None
    not_after: str | None = None
    san: list[str] = Field(default_factory=list)
    fingerprint_sha256: str | None = None
    is_expired: bool | None = None

class PortCheckRequest(BaseModel):
    host: str = Field(min_length=1, max_length=255)
    ports: list[int] = Field(min_length=1, max_length=32)
    timeout: float = Field(default=2.0, gt=0.1, le=5.0)

    @field_validator("ports")
    @classmethod
    def unique_ports(cls, value: list[int]) -> list[int]:
        if len(set(value)) != len(value):
            raise ValueError("Ports must be unique.")
        return value

class PortResult(BaseModel):
    port: int
    open: bool
    addresses: list[str] = Field(default_factory=list)
    error: str | None = None

class PortCheckResponse(BaseModel):
    host: str
    results: list[PortResult]

class RobotsRequest(LiveURLRequest):
    pass

class RobotsResponse(BaseModel):
    url: str
    status_code: int
    user_agents: dict[str, dict[str, list[str]]]
    sitemaps: list[str]

class SitemapRequest(LiveURLRequest):
    pass

class SitemapResponse(BaseModel):
    url: str
    status_code: int
    is_index: bool
    urls: list[dict[str, str | None]]
    child_sitemaps: list[str]
    valid_xml: bool

class OGRequest(LiveURLRequest):
    pass

class OGResponse(BaseModel):
    url: str
    status_code: int
    tags: dict[str, str]
    title: str | None = None
    description: str | None = None
    image: str | None = None
    canonical_url: str | None = None
    site_name: str | None = None

class EmailHeaderRequest(BaseModel):
    headers: str = Field(min_length=1, max_length=1_000_000)

class EmailHeaderResponse(BaseModel):
    from_address: str | None = None
    to_addresses: list[str] = Field(default_factory=list)
    cc_addresses: list[str] = Field(default_factory=list)
    reply_to: list[str] = Field(default_factory=list)
    subject: str | None = None
    message_id: str | None = None
    date: str | None = None
    received_hops: list[dict[str, str | None]] = Field(default_factory=list)
    authentication_results: list[str] = Field(default_factory=list)
    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None

class JSONRequest(BaseModel):
    value: str = Field(max_length=4_000_000)
    mode: Literal["validate", "pretty", "minify"] = "validate"

class JSONResponseModel(BaseModel):
    valid: bool
    value: str | None = None
    type: str | None = None
    error: str | None = None
    line: int | None = None
    column: int | None = None

class RegexRequest(BaseModel):
    pattern: str = Field(max_length=10000)
    text: str = Field(max_length=1_000_000)
    flags: str = ""

class RegexMatch(BaseModel):
    match: str
    start: int
    end: int
    groups: list[str | None]
    named_groups: dict[str, str | None]

class RegexResponse(BaseModel):
    valid: bool
    matches: list[RegexMatch] = Field(default_factory=list)
    error: str | None = None
