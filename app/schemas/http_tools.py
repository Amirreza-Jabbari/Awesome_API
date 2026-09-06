"""Schemas for the Web & HTTP developer toolset.

Covers the HTTP request builder/inspector, curl generator, raw HTTP header
generator and URL query-string parser.
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

HTTPMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]


def _valid_method(value: str) -> str:
    if value not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        raise ValueError(f"Unsupported HTTP method: {value}")
    return value


class HTTPQueryParam(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    value: str = Field(max_length=4096)


class HTTPAuth(BaseModel):
    type: Literal["none", "basic", "bearer"] = "none"
    username: str | None = Field(default=None, max_length=1024)
    password: str | None = Field(default=None, max_length=4096)
    token: str | None = Field(default=None, max_length=8192)

    @model_validator(mode="after")
    def validate_fields(self) -> HTTPAuth:
        if self.type == "basic" and (not self.username or self.password is None):
            raise ValueError("Basic auth requires username and password.")
        if self.type == "bearer" and not self.token:
            raise ValueError("Bearer auth requires a token.")
        return self


class HTTPRequestSpec(BaseModel):
    method: HTTPMethod = "GET"
    url: str = Field(min_length=1, max_length=4096)
    headers: dict[str, str] = Field(default_factory=dict, max_length=60)
    query: list[HTTPQueryParam] = Field(default_factory=list, max_length=100)
    body: str | None = Field(default=None, max_length=1_000_000)
    body_type: Literal["text", "json", "form", "xml"] = "text"
    auth: HTTPAuth = Field(default_factory=HTTPAuth)

    @field_validator("headers")
    @classmethod
    def validate_header_names(cls, value: dict[str, str]) -> dict[str, str]:
        for raw_name in value:
            name = raw_name.strip()
            if not name or not all(ch.isalnum() or ch in "-_." for ch in name):
                raise ValueError(f"Invalid header name: {raw_name!r}")
            if name.lower() == "host":
                raise ValueError("Use the URL to set the Host header; remove 'Host'.")
        return value


class HTTPRequestBuilderRequest(BaseModel):
    request: HTTPRequestSpec
    execute: bool = False
    timeout: float = Field(default=10.0, ge=0.5, le=60.0)


class RedirectHop(BaseModel):
    status_code: int
    location: str


class HTTPRequestBuilderResponse(BaseModel):
    mode: Literal["build", "execute"]
    method: str
    url: str
    final_url: str | None = None
    host: str | None = None
    port: int | None = None
    ip_addresses: list[str] = Field(default_factory=list)
    ssrf_checked: bool = False
    headers: dict[str, str] = Field(default_factory=dict)
    raw_query: str = ""
    body: str | None = None
    body_length: int = 0
    content_type: str | None = None
    curl: str | None = None
    status_code: int | None = None
    reason: str | None = None
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body: str | None = None
    response_truncated: bool = False
    response_size: int = 0
    is_json: bool = False
    elapsed_ms: float | None = None
    redirects: list[RedirectHop] = Field(default_factory=list)
    error: str | None = None


class HTTPInspectRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096)
    method: HTTPMethod = "GET"
    headers: dict[str, str] = Field(default_factory=dict, max_length=40)
    body: str | None = Field(default=None, max_length=1_000_000)
    follow_redirects: bool = True
    max_redirects: int = Field(default=5, ge=0, le=20)
    max_body_size: int = Field(default=1_000_000, ge=1024, le=5_242_880)
    timeout: float = Field(default=10.0, ge=0.5, le=60.0)


class InspectCookie(BaseModel):
    name: str
    value: str


class HTTPInspectResponse(BaseModel):
    valid: bool
    error: str | None = None
    url: str
    final_url: str | None = None
    status_code: int | None = None
    reason: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: list[InspectCookie] = Field(default_factory=list)
    body_preview: str | None = None
    body_size: int = 0
    body_truncated: bool = False
    is_json: bool = False
    json_type: str | None = None
    content_type: str | None = None
    charset: str | None = None
    elapsed_ms: float | None = None
    redirects: list[RedirectHop] = Field(default_factory=list)
    host: str | None = None
    ip_addresses: list[str] = Field(default_factory=list)
    ssrf_checked: bool = True


class CurlGenerateRequest(BaseModel):
    method: HTTPMethod = "GET"
    url: str = Field(min_length=1, max_length=4096)
    headers: dict[str, str] = Field(default_factory=dict, max_length=60)
    query: list[HTTPQueryParam] = Field(default_factory=list, max_length=100)
    body: str | None = Field(default=None, max_length=1_000_000)
    body_type: Literal["text", "json", "form", "xml"] = "text"
    auth: HTTPAuth = Field(default_factory=HTTPAuth)
    pretty: bool = True
    include_headers: bool = False
    follow_redirects: bool = False
    compressed: bool = False
    silent: bool = False


class CurlGenerateResponse(BaseModel):
    command: str
    flags: dict[str, Any] = Field(default_factory=dict)


class HTTPHeaderPair(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    value: str = Field(max_length=8192)


class HeadersGenerateRequest(BaseModel):
    headers: list[HTTPHeaderPair] = Field(default_factory=list, max_length=200)
    style: Literal["raw", "lowercase", "uppercase"] = "raw"
    include_content_length: bool = False


class NormalizedHeader(BaseModel):
    name: str
    value: str


class HeaderIssue(BaseModel):
    index: int
    issue: str


class HeadersGenerateResponse(BaseModel):
    raw: str
    count: int
    normalized: list[NormalizedHeader]
    issues: list[HeaderIssue] = Field(default_factory=list)


class URLParseRequest(BaseModel):
    url: str = Field(min_length=1, max_length=8192)


class URLQueryParam(BaseModel):
    name: str
    value: str


class URLParseResponse(BaseModel):
    valid: bool
    error: str | None = None
    scheme: str | None = None
    host: str | None = None
    hostname: str | None = None
    port: int | None = None
    path: str = ""
    raw_query: str = ""
    query: list[URLQueryParam] = Field(default_factory=list)
    params: dict[str, str] = Field(default_factory=dict)
    fragment: str = ""
    username: str | None = None
    password: str | None = None
    url_without_query: str | None = None
