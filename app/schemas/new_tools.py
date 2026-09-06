"""Schemas for the ten new developer/analysis tool endpoints."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

# ── Website Technology Detector ───────────────────────────────────────────────

class TechDetectRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class TechDetection(BaseModel):
    name: str = Field(description="Detected technology name.")
    category: str = Field(
        description=(
            "Category: cms, framework, library, server, analytics, "
            "font, cdn, language, or other."
        )
    )
    confidence: Literal["high", "medium", "low"] = Field(
        description="Detection confidence."
    )
    evidence: str = Field(description="How the technology was detected.")


class TechDetectResponse(BaseModel):
    url: str
    status_code: int
    technologies: list[TechDetection]
    server: str | None = None
    powered_by: str | None = None


# ── Redirect Analyzer ─────────────────────────────────────────────────────────

class RedirectHop(BaseModel):
    url: str = Field(description="URL at this hop.")
    status_code: int = Field(description="HTTP status code.")
    location: str | None = Field(
        default=None, description="Redirect Location header value."
    )
    redirect_type: str | None = Field(
        default=None,
        description="Redirect type: permanent, temporary, or refresh.",
    )


class RedirectAnalyzeRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    max_hops: int = Field(
        default=10, ge=1, le=20, description="Maximum number of redirects to follow."
    )


class RedirectAnalyzeResponse(BaseModel):
    url: str = Field(description="Original URL.")
    final_url: str = Field(description="Final URL after all redirects.")
    hops: list[RedirectHop]
    total_hops: int
    is_loop: bool = Field(
        default=False, description="Whether a redirect loop was detected."
    )
    has_https_redirect: bool = Field(
        default=False, description="Whether HTTP was upgraded to HTTPS."
    )
    has_www_redirect: bool = Field(
        default=False,
        description="Whether non-www was redirected to www or vice-versa.",
    )


# ── DNSSEC Validator ──────────────────────────────────────────────────────────

class DNSSECRequest(BaseModel):
    domain: str = Field(min_length=1, max_length=255)


class DNSSECRecord(BaseModel):
    record_type: str
    flags: int | None = None
    protocol: int | None = None
    algorithm: int | None = None
    digest_type: int | None = None
    key_tag: int | None = None
    value: str


class DNSSECResponse(BaseModel):
    domain: str
    dnssec_enabled: bool = Field(
        description="Whether the domain has DNSKEY/DS records."
    )
    has_dnskey: bool
    has_ds: bool
    has_rrsig: bool
    chain_valid: bool | None = Field(
        default=None,
        description=(
            "Whether the DS-to-DNSKEY chain is consistent, null if unverifiable."
        ),
    )
    records: list[DNSSECRecord]
    error: str | None = None


# ── Email Domain Analyzer ─────────────────────────────────────────────────────

class EmailDomainRequest(BaseModel):
    domain: str = Field(min_length=1, max_length=255)


class MXRecord(BaseModel):
    priority: int
    host: str


class EmailDomainResponse(BaseModel):
    domain: str
    has_mx: bool
    mx_records: list[MXRecord]
    spf_record: str | None = None
    spf_valid: bool | None = Field(
        default=None, description="Whether the SPF record parsed successfully."
    )
    dmarc_record: str | None = None
    dmarc_policy: str | None = Field(
        default=None, description="DMARC policy: none, quarantine, or reject."
    )
    dmarc_pct: int | None = Field(
        default=None, description="DMARC percentage tag value."
    )
    is_disposable: bool
    is_free_provider: bool
    mail_provider: str | None = Field(
        default=None,
        description=(
            "Inferred mail provider (e.g. Google, Microsoft, ProtonMail)."
        ),
    )
    has_dmarc: bool
    has_spf: bool


# ── File Metadata Extractor ───────────────────────────────────────────────────

class FileMetadataRequest(BaseModel):
    data: str = Field(
        min_length=4,
        max_length=6_000_000,
        description="Base64-encoded file content.",
    )
    filename: str | None = Field(
        default=None,
        max_length=255,
        description="Optional filename for extension-based detection.",
    )


class FileMetadataResponse(BaseModel):
    mime_type: str = Field(description="Detected MIME type.")
    extension: str | None = Field(
        default=None, description="Guessed file extension (with dot)."
    )
    size_bytes: int = Field(
        description="Size of the decoded file in bytes."
    )
    magic_match: bool = Field(
        description="Whether the magic bytes match the declared MIME type."
    )
    description: str = Field(
        description="Human-readable description of the file type."
    )


# ── Content Type Detector ─────────────────────────────────────────────────────

class ContentTypeRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    check_body: bool = Field(
        default=False,
        description="When true, fetches the first 512 bytes for magic-byte sniffing.",
    )


class ContentTypeResponse(BaseModel):
    url: str
    declared_type: str | None = Field(
        default=None, description="Content-Type header value."
    )
    charset: str | None = Field(default=None)
    mime_type: str | None = Field(
        default=None, description="MIME type from Content-Type header."
    )
    body_sniffed_type: str | None = Field(
        default=None,
        description="MIME type inferred from magic bytes (when check_body=true).",
    )
    is_html: bool
    is_json: bool
    is_xml: bool
    is_binary: bool


# ── Canonical URL Checker ─────────────────────────────────────────────────────

class CanonicalCheckRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class CanonicalCheckResponse(BaseModel):
    url: str = Field(description="Original URL.")
    final_url: str = Field(description="Final URL after redirects.")
    canonical_url: str | None = Field(
        default=None,
        description="Canonical URL from <link rel=canonical> or meta tag.",
    )
    has_canonical: bool
    is_self_referencing: bool = Field(
        default=False, description="Whether the canonical points to the same URL."
    )
    is_valid_canonical: bool | None = Field(
        default=None,
        description="Whether the canonical URL itself returns 200.",
    )
    status_code: int
    rel_canonical_header: str | None = Field(
        default=None, description="Canonical from HTTP Link header."
    )


# ── Image Metadata Analyzer ───────────────────────────────────────────────────

class ImageMetadataRequest(BaseModel):
    data: str = Field(
        min_length=4,
        max_length=10_000_000,
        description="Base64-encoded image data.",
    )
    filename: str | None = Field(default=None, max_length=255)


class ImageMetadataResponse(BaseModel):
    format: str | None = Field(
        default=None, description="Image format (JPEG, PNG, GIF, TIFF, WEBP, BMP)."
    )
    width: int | None = None
    height: int | None = None
    mode: str | None = Field(
        default=None, description="Color mode (RGB, RGBA, L, CMYK, etc.)."
    )
    has_exif: bool = Field(default=False)
    exif: dict[str, str] = Field(
        default_factory=dict,
        description="Decoded EXIF tags (camera, date, GPS, etc.).",
    )
    icc_profile: str | None = Field(
        default=None, description="ICC color profile name if present."
    )
    is_animated: bool = Field(default=False)
    frame_count: int = Field(
        default=1, description="Number of frames (for animated images)."
    )
    error: str | None = None


# ── Password Strength Analyzer ────────────────────────────────────────────────

class PasswordStrengthRequest(BaseModel):
    password: str = Field(min_length=1, max_length=1024)


class PasswordStrengthResponse(BaseModel):
    score: int = Field(
        ge=0, le=5, description="Strength score from 0 (very weak) to 5 (very strong)."
    )
    entropy_bits: float = Field(description="Estimated entropy in bits.")
    crack_time_display: str = Field(
        description="Human-readable estimated crack time."
    )
    has_uppercase: bool
    has_lowercase: bool
    has_numbers: bool
    has_special: bool
    has_unicode: bool
    length: int
    character_variety: int = Field(
        description="Number of distinct character classes used."
    )
    common_pattern: bool = Field(
        default=False,
        description="Whether the password matches a common weak pattern.",
    )
    feedback: list[str] = Field(
        default_factory=list, description="Actionable improvement suggestions."
    )


# ── Unicode Inspector ─────────────────────────────────────────────────────────

class UnicodeInspectRequest(BaseModel):
    text: str = Field(
        min_length=1, max_length=4096, description="Text to inspect (one or more characters)."
    )


class UnicodeCharInfo(BaseModel):
    char: str = Field(description="The character.")
    codepoint: str = Field(description="Hex codepoint (e.g. U+0041).")
    name: str = Field(description="Unicode character name.")
    category: str = Field(description="General category (Lu, Ll, Nd, etc.).")
    category_name: str = Field(description="Human-readable category name.")
    script: str = Field(description="Script (Latin, Cyrillic, Han, etc.).")
    block: str = Field(description="Unicode block name.")
    bidirectional: str = Field(description="Bidirectional class.")
    is_alphabetic: bool
    is_numeric: bool
    is_whitespace: bool
    is_control: bool
    decimal_value: int | None = Field(
        default=None, description="Decimal digit value if numeric."
    )


class UnicodeInspectResponse(BaseModel):
    input: str
    length: int = Field(description="Number of characters.")
    total_codepoints: int
    scripts: list[str] = Field(description="Unique scripts found.")
    categories: list[str] = Field(description="Unique categories found.")
    characters: list[UnicodeCharInfo]
