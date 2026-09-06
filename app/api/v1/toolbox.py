"""Developer, encoding, parsing and security utility endpoints."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from app.core.dependencies import (
    get_dns_tools_service,
    get_file_metadata_service,
    get_toolbox_service,
    get_web_tools_service,
)
from app.schemas.new_tools import (
    CanonicalCheckRequest,
    CanonicalCheckResponse,
    ContentTypeRequest,
    ContentTypeResponse,
    DNSSECRequest,
    DNSSECResponse,
    EmailDomainRequest,
    EmailDomainResponse,
    FileMetadataRequest,
    FileMetadataResponse,
    ImageMetadataRequest,
    ImageMetadataResponse,
    PasswordStrengthRequest,
    PasswordStrengthResponse,
    RedirectAnalyzeRequest,
    RedirectAnalyzeResponse,
    TechDetectRequest,
    TechDetectResponse,
    UnicodeInspectRequest,
    UnicodeInspectResponse,
)
from app.schemas.toolbox import (
    CodecRequest,
    CodecResponse,
    EmailHeaderRequest,
    EmailHeaderResponse,
    HashGenerateRequest,
    HashGenerateResponse,
    HashIdentifyRequest,
    HashIdentifyResponse,
    HTMLCodecRequest,
    HTMLCodecResponse,
    HTTPHeadersRequest,
    HTTPHeadersResponse,
    JSONRequest,
    JSONResponseModel,
    JWTGenerateRequest,
    JWTGenerateResponse,
    JWTInspectRequest,
    JWTInspectResponse,
    LiveURLRequest,
    OGRequest,
    OGResponse,
    PortCheckRequest,
    PortCheckResponse,
    RegexRequest,
    RegexResponse,
    RobotsRequest,
    RobotsResponse,
    SecurityHeadersResponse,
    SitemapRequest,
    SitemapResponse,
    TimestampRequest,
    TimestampResponse,
    TimezoneRequest,
    TimezoneResponse,
    TLSLookupRequest,
    TLSLookupResponse,
    ULIDRequest,
    ULIDResponse,
    ULIDValidateRequest,
    ULIDValidationResponse,
    URLCodecRequest,
    URLCodecResponse,
    UUIDRequest,
    UUIDResponse,
    UUIDValidateRequest,
)
from app.services.dns_tools_service import DNSToolsService
from app.services.file_metadata_service import FileMetadataService
from app.services.toolbox_service import ToolboxService
from app.services.web_tools_service import WebToolsService

router = APIRouter()


# ── JWT Inspector ─────────────────────────────────────────────────────────────

@router.post(
    "/jwt/inspect",
    response_model=JWTInspectResponse,
    tags=["Web Security"],
    summary="Inspect a JWT token",
    description=(
        "Decodes the JWT header and payload locally. Reports algorithm, type, "
        "standard claims, signature presence and expiration state. **Does not** "
        "verify the signature and never needs the signing secret."
    ),
)
async def jwt_inspect(
    payload: JWTInspectRequest,
    service: ToolboxService = Depends(get_toolbox_service),
) -> dict[str, Any]:
    return service.inspect_jwt(payload.token)


# ── JWT Generator ─────────────────────────────────────────────────────────────

@router.post(
    "/jwt/generate",
    response_model=JWTGenerateResponse,
    tags=["Web Security"],
    summary="Generate a signed JWT",
    description=(
        "Creates an HS256/HS384/HS512-signed JWT locally using PyJWT. The "
        "secret must provide at least 256 bits of UTF-8 key material, and only "
        "the symmetric HS algorithms are allowed. Adds iat and exp claims, "
        "carries standard claims (iss, sub, aud, jti) when provided, and never "
        "logs the secret. No external signing service is used."
    ),
)
async def jwt_generate(
    payload: JWTGenerateRequest,
    service: ToolboxService = Depends(get_toolbox_service),
) -> dict[str, Any]:
    return service.generate_jwt(
        payload.payload, payload.algorithm, payload.secret, payload.expires_in,
        payload.issuer, payload.subject, payload.audience, payload.token_id,
        payload.headers,
    )


# ── Hash Generator ────────────────────────────────────────────────────────────

@router.post(
    "/hash/generate",
    response_model=HashGenerateResponse,
    tags=["Data & Encoding"],
    summary="Generate a hash digest",
    description=(
        "Computes a cryptographic hash of the supplied input. Supports MD5, "
        "SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, BLAKE2b and BLAKE2s. "
        "Input may be UTF-8 text, hex bytes or Base64 bytes."
    ),
)
async def hash_generate(
    payload: HashGenerateRequest,
    service: ToolboxService = Depends(get_toolbox_service),
) -> dict[str, Any]:
    return service.hash_generate(payload.input, payload.algorithm, payload.encoding)


# ── Hash Identifier ───────────────────────────────────────────────────────────

@router.post(
    "/hash/identify",
    response_model=HashIdentifyResponse,
    tags=["Data & Encoding"],
    summary="Identify a hash algorithm",
    description=(
        "Uses digest length and character encoding to produce heuristic "
        "candidates for an unknown hash. Cannot prove which algorithm "
        "produced an arbitrary hash."
    ),
)
async def hash_identify(
    payload: HashIdentifyRequest,
    service: ToolboxService = Depends(get_toolbox_service),
) -> dict[str, Any]:
    return service.hash_identify(payload.hash)


# ── Base64 Encoder / Decoder ─────────────────────────────────────────────────

@router.post(
    "/base64",
    response_model=CodecResponse,
    tags=["Data & Encoding"],
    summary="Encode or decode Base64",
    description=(
        "Base64-encodes or decodes a value. Use `mode=encode|decode` and "
        "`encoding=utf-8|hex`. Hex input/output makes binary payloads "
        "representable without requiring a file upload."
    ),
)
async def base64_codec(
    payload: CodecRequest,
    service: ToolboxService = Depends(get_toolbox_service),
) -> dict[str, Any]:
    return {
        "value": service.codec(payload.value, payload.mode, payload.encoding),
        "encoding": payload.encoding,
    }


# ── URL Encoder / Decoder ────────────────────────────────────────────────────

@router.post(
    "/url/codec",
    response_model=URLCodecResponse,
    tags=["Data & Encoding"],
    summary="Percent-encode or decode a URL component",
    description=(
        "Percent-encodes or decodes a URL component. Set `component=false` "
        "when encoding a larger URL while preserving common URL delimiters."
    ),
)
async def url_codec(
    payload: URLCodecRequest,
    service: ToolboxService = Depends(get_toolbox_service),
) -> dict[str, Any]:
    return {
        "value": service.url_codec(payload.value, payload.mode, payload.component),
        "mode": payload.mode,
    }


# ── HTML Entity Encoder / Decoder ────────────────────────────────────────────

@router.post(
    "/html/entities",
    response_model=HTMLCodecResponse,
    tags=["Data & Encoding"],
    summary="Encode or decode HTML entities",
    description=(
        "HTML-escapes or unescapes text using Python's standards-based "
        "HTML implementation."
    ),
)
async def html_entities(
    payload: HTMLCodecRequest,
    service: ToolboxService = Depends(get_toolbox_service),
) -> dict[str, Any]:
    return {
        "value": service.html_codec(payload.value, payload.mode, payload.quote),
        "mode": payload.mode,
    }


# ── UUID Generator / Validator ───────────────────────────────────────────────

@router.post(
    "/uuid/generate",
    response_model=UUIDResponse,
    tags=["Data & Encoding"],
    summary="Generate a UUID",
    description=(
        "Generates UUID versions 1, 3, 4, 5 and 7. Versions 3/5 accept "
        "built-in namespace names (`dns`, `url`, `oid`, `x500`) or an "
        "explicit namespace UUID."
    ),
)
async def uuid_generate(
    payload: UUIDRequest,
    service: ToolboxService = Depends(get_toolbox_service),
) -> dict[str, Any]:
    u = service.uuid_generate(payload.version, payload.namespace, payload.name)
    return {"uuid": str(u), "version": u.version, "variant": u.variant}


@router.post(
    "/uuid/validate",
    response_model=UUIDResponse,
    tags=["Data & Encoding"],
    summary="Validate a UUID",
    description="Validates a UUID string and reports its version and variant.",
)
async def uuid_validate(
    payload: UUIDValidateRequest,
    service: ToolboxService = Depends(get_toolbox_service),
) -> dict[str, Any]:
    return service.uuid_validate(payload.uuid)


# ── ULID Generator / Validator ───────────────────────────────────────────────

@router.post(
    "/ulid/generate",
    response_model=ULIDResponse,
    tags=["Data & Encoding"],
    summary="Generate ULID(s)",
    description="Generates canonical 26-character ULIDs.",
)
async def ulid_generate(
    payload: ULIDRequest,
    service: ToolboxService = Depends(get_toolbox_service),
) -> dict[str, Any]:
    return {"ulids": service.ulid_generate(payload.count)}


@router.post(
    "/ulid/validate",
    response_model=ULIDValidationResponse,
    tags=["Data & Encoding"],
    summary="Validate a ULID",
    description=(
        "Validates a ULID and decodes its embedded millisecond timestamp."
    ),
)
async def ulid_validate(
    payload: ULIDValidateRequest,
    service: ToolboxService = Depends(get_toolbox_service),
) -> dict[str, Any]:
    return service.ulid_validate(payload.ulid)


# ── Timestamp Converter ──────────────────────────────────────────────────────

@router.post(
    "/timestamp/convert",
    response_model=TimestampResponse,
    tags=["Time & Date"],
    summary="Convert a timestamp or datetime string",
    description=(
        "Converts Unix seconds or an ISO-8601 datetime into UTC and an "
        "IANA timezone. Exactly one input representation is required."
    ),
)
async def timestamp_convert(
    payload: TimestampRequest,
    service: ToolboxService = Depends(get_toolbox_service),
) -> dict[str, Any]:
    return service.timestamp(payload.timestamp, payload.datetime, payload.timezone)


# ── Timezone Lookup ──────────────────────────────────────────────────────────

@router.post(
    "/timezone/lookup",
    response_model=TimezoneResponse,
    tags=["Time & Date"],
    summary="Look up a timezone by IP or coordinates",
    description=(
        "Accepts either an IP address or latitude/longitude. IP lookups "
        "reuse the GeoIP service; coordinate lookups use a no-key source."
    ),
)
async def timezone_lookup(
    payload: TimezoneRequest,
    service: WebToolsService = Depends(get_web_tools_service),
) -> dict[str, Any]:
    return await service.timezone(payload.ip, payload.latitude, payload.longitude)


# ── HTTP Headers Analyzer ────────────────────────────────────────────────────

@router.post(
    "/http-headers/analyze",
    response_model=HTTPHeadersResponse,
    tags=["Web Security"],
    summary="Analyze HTTP response headers",
    description=(
        "Analyzes a supplied response-header map locally, grouping security, "
        "cache, CORS, server and content signals. No network request is made."
    ),
)
async def headers_analyze(
    payload: HTTPHeadersRequest,
    service: ToolboxService = Depends(get_toolbox_service),
) -> dict[str, Any]:
    return service.analyze_headers(payload.headers)


# ── Security Headers Checker ─────────────────────────────────────────────────

@router.post(
    "/security-headers/check",
    response_model=SecurityHeadersResponse,
    tags=["Web Security"],
    summary="Check security headers on a live URL",
    description=(
        "Fetches a live HTTPS/HTTP target and checks CSP, HSTS, "
        "X-Content-Type-Options, Referrer-Policy, Permissions-Policy and "
        "X-Frame-Options. Returns a transparent presence score."
    ),
)
async def security_headers(
    payload: LiveURLRequest,
    service: WebToolsService = Depends(get_web_tools_service),
) -> dict[str, Any]:
    return await service.security_headers(payload.url)


# ── SSL/TLS Certificate Lookup ───────────────────────────────────────────────

@router.post(
    "/tls/lookup",
    response_model=TLSLookupResponse,
    tags=["Web Security"],
    summary="Look up a TLS certificate",
    description=(
        "Connects to a public TLS target and returns certificate subject, "
        "issuer, serial, validity, SANs and SHA-256 fingerprint."
    ),
)
async def tls_lookup(
    payload: TLSLookupRequest,
    service: WebToolsService = Depends(get_web_tools_service),
) -> dict[str, Any]:
    return await service.tls_lookup(payload.host, payload.port)


# ── Port Status Checker ──────────────────────────────────────────────────────

@router.post(
    "/ports/check",
    response_model=PortCheckResponse,
    tags=["IP & Network"],
    summary="Check TCP port status",
    description=(
        "Checks a bounded list of TCP ports on a public IP/hostname. "
        "Private, loopback, link-local and reserved targets are blocked."
    ),
)
async def ports_check(
    payload: PortCheckRequest,
    service: WebToolsService = Depends(get_web_tools_service),
) -> dict[str, Any]:
    return await service.port_check(payload.host, payload.ports, payload.timeout)


# ── robots.txt Analyzer ──────────────────────────────────────────────────────

@router.post(
    "/robots/analyze",
    response_model=RobotsResponse,
    tags=["Web Analysis"],
    summary="Analyze a robots.txt file",
    description=(
        "Retrieves and parses robots.txt. Exposes user-agent allow/disallow "
        "rules and Sitemap declarations."
    ),
)
async def robots(
    payload: RobotsRequest,
    service: WebToolsService = Depends(get_web_tools_service),
) -> dict[str, Any]:
    return await service.robots(payload.url)


# ── Sitemap Analyzer ─────────────────────────────────────────────────────────

@router.post(
    "/sitemap/analyze",
    response_model=SitemapResponse,
    tags=["Web Analysis"],
    summary="Analyze an XML sitemap",
    description=(
        "Parses XML sitemap files and sitemap indexes, returning URLs, "
        "last-modified values and child sitemap locations."
    ),
)
async def sitemap(
    payload: SitemapRequest,
    service: WebToolsService = Depends(get_web_tools_service),
) -> dict[str, Any]:
    return await service.sitemap(payload.url)


# ── Open Graph Analyzer ──────────────────────────────────────────────────────

@router.post(
    "/opengraph/analyze",
    response_model=OGResponse,
    tags=["Web Analysis"],
    summary="Extract Open Graph metadata",
    description=(
        "Extracts og:* metadata including title, description, image, "
        "canonical URL and site name."
    ),
)
async def opengraph(
    payload: OGRequest,
    service: WebToolsService = Depends(get_web_tools_service),
) -> dict[str, Any]:
    return await service.open_graph(payload.url)


# ── Email Header Analyzer ────────────────────────────────────────────────────

@router.post(
    "/email/analyze-headers",
    response_model=EmailHeaderResponse,
    tags=["Email"],
    summary="Analyze raw email headers",
    description=(
        "Parses RFC-style email headers and returns sender/recipient "
        "metadata, Message-ID, Received hops and SPF/DKIM/DMARC results."
    ),
)
async def email_headers(
    payload: EmailHeaderRequest,
    service: ToolboxService = Depends(get_toolbox_service),
) -> dict[str, Any]:
    return service.parse_email_headers(payload.headers)


# ── JSON Formatter & Validator ───────────────────────────────────────────────

@router.post(
    "/json",
    response_model=JSONResponseModel,
    tags=["Data & Encoding"],
    summary="Format or validate JSON",
    description=(
        "Supports `validate`, `pretty` and `minify` modes. Reports JSON "
        "syntax line/column information without executing embedded content."
    ),
)
async def json_tool(
    payload: JSONRequest,
    service: ToolboxService = Depends(get_toolbox_service),
) -> dict[str, Any]:
    return service.json_tool(payload.value, payload.mode)


# ── Regex Tester ─────────────────────────────────────────────────────────────

@router.post(
    "/regex",
    response_model=RegexResponse,
    tags=["Validation & Text"],
    summary="Test a regular expression",
    description=(
        "Compiles a Python regular expression and returns matches, offsets, "
        "capture groups and named groups, or a precise compile error. "
        "Supported flags: `i`, `m`, `s`, `x`, `a`."
    ),
)
async def regex_tool(
    payload: RegexRequest,
    service: ToolboxService = Depends(get_toolbox_service),
) -> dict[str, Any]:
    return service.regex_tool(payload.pattern, payload.text, payload.flags)


# ═══════════════════════════════════════════════════════════════════════════════
#  New Generation Tools
# ═══════════════════════════════════════════════════════════════════════════════


# ── Website Technology Detector ───────────────────────────────────────────────

@router.post(
    "/tech-detect",
    response_model=TechDetectResponse,
    tags=["Web Analysis"],
    summary="Detect website technologies",
    description=(
        "Fetches a live URL through the shared SSRF-hardened web fetcher and "
        "identifies the technologies powering the site — CMS, framework, "
        "server, CDN, analytics, fonts and hosting platform — using HTTP "
        "headers and HTML content fingerprinting. No third-party service is "
        "queried; detection is purely heuristic."
    ),
)
async def tech_detect(
    payload: TechDetectRequest,
    service: WebToolsService = Depends(get_web_tools_service),
) -> dict[str, Any]:
    return await service.detect_technologies(payload.url)


# ── Redirect Analyzer ─────────────────────────────────────────────────────────

@router.post(
    "/redirect/analyze",
    response_model=RedirectAnalyzeResponse,
    tags=["Web Analysis"],
    summary="Trace URL redirect chains",
    description=(
        "Follows the full redirect chain of a URL through the secure web "
        "fetcher, reporting each hop's status code and Location header. "
        "Identifies redirect loops, HTTP→HTTPS upgrades and www↔non-www "
        "redirects. Useful for SEO audits and link-integrity checks."
    ),
)
async def redirect_analyze(
    payload: RedirectAnalyzeRequest,
    service: WebToolsService = Depends(get_web_tools_service),
) -> dict[str, Any]:
    return await service.analyze_redirects(payload.url, payload.max_hops)


# ── DNSSEC Validator ──────────────────────────────────────────────────────────

@router.post(
    "/dnssec/validate",
    response_model=DNSSECResponse,
    tags=["Domain & DNS"],
    summary="Validate DNSSEC status of a domain",
    description=(
        "Queries DNSKEY, DS and RRSIG records for a domain using the shared "
        "DNS provider and reports whether DNSSEC is enabled, whether the "
        "DS→DNSKEY chain is consistent, and lists the raw DNSSEC records. "
        "No external lookup service is required."
    ),
)
async def dnssec_validate(
    payload: DNSSECRequest,
    service: DNSToolsService = Depends(get_dns_tools_service),
) -> dict[str, Any]:
    return await service.dnssec_validate(payload.domain)


# ── Email Domain Analyzer ─────────────────────────────────────────────────────

@router.post(
    "/email/analyze-domain",
    response_model=EmailDomainResponse,
    tags=["Email"],
    summary="Analyze an email domain's mail infrastructure",
    description=(
        "Inspects a domain's email setup: MX records, SPF record validity, "
        "DMARC policy and percentage, disposable/free-provider classification "
        "and the inferred mail provider. Uses standard DNS lookups only — no "
        "paid or key-required services."
    ),
)
async def email_domain_analyze(
    payload: EmailDomainRequest,
    service: DNSToolsService = Depends(get_dns_tools_service),
) -> dict[str, Any]:
    return await service.email_domain_analyze(payload.domain)


# ── File Metadata Extractor ───────────────────────────────────────────────────

@router.post(
    "/file/metadata",
    response_model=FileMetadataResponse,
    tags=["Files & Metadata"],
    summary="Extract file type metadata from Base64 data",
    description=(
        "Detects the MIME type of Base64-encoded file content using magic-byte "
        "sniffing. Returns the detected type, guessed extension, decoded size "
        "and a textual description. Optionally accepts a filename for "
        "extension-based hints. No file is uploaded or persisted."
    ),
)
async def file_metadata(
    payload: FileMetadataRequest,
    service: FileMetadataService = Depends(get_file_metadata_service),
) -> dict[str, Any]:
    return service.extract_file_metadata(payload.data, payload.filename)


# ── Content Type Detector ─────────────────────────────────────────────────────

@router.post(
    "/content-type/detect",
    response_model=ContentTypeResponse,
    tags=["Files & Metadata"],
    summary="Detect a web resource's content type",
    description=(
        "Fetches a URL through the secure web fetcher and reports the declared "
        "Content-Type header, charset, and — when requested — the body-sniffed "
        "MIME type from magic bytes. Useful for debugging misconfigured "
        "servers and verifying content negotiation."
    ),
)
async def content_type_detect(
    payload: ContentTypeRequest,
    service: WebToolsService = Depends(get_web_tools_service),
) -> dict[str, Any]:
    return await service.detect_content_type(payload.url, payload.check_body)


# ── Canonical URL Checker ─────────────────────────────────────────────────────

@router.post(
    "/canonical/check",
    response_model=CanonicalCheckResponse,
    tags=["Web Analysis"],
    summary="Check a page's canonical URL",
    description=(
        "Fetches a page and extracts its canonical URL from the HTML `<link "
        "rel=canonical>` tag or an HTTP `Link: rel=canonical` header. Reports "
        "whether a canonical is present, whether it self-references, and the "
        "final URL after redirects. Essential for SEO duplicate-content audits."
    ),
)
async def canonical_check(
    payload: CanonicalCheckRequest,
    service: WebToolsService = Depends(get_web_tools_service),
) -> dict[str, Any]:
    return await service.check_canonical(payload.url)


# ── Image Metadata Analyzer ───────────────────────────────────────────────────

@router.post(
    "/image/metadata",
    response_model=ImageMetadataResponse,
    tags=["Files & Metadata"],
    summary="Extract image metadata from Base64 data",
    description=(
        "Decodes Base64-encoded image data and extracts dimensions, format, "
        "color mode, EXIF tags (camera, date, GPS), ICC color profile and "
        "animation frame count using Pillow. Supports JPEG, PNG, GIF, WEBP, "
        "TIFF, BMP and more. No external service is queried."
    ),
)
async def image_metadata(
    payload: ImageMetadataRequest,
    service: FileMetadataService = Depends(get_file_metadata_service),
) -> dict[str, Any]:
    return service.extract_image_metadata(payload.data, payload.filename)


# ── Password Strength Analyzer ────────────────────────────────────────────────

@router.post(
    "/password/strength",
    response_model=PasswordStrengthResponse,
    tags=["Validation & Text"],
    summary="Analyze password strength",
    description=(
        "Evaluates a password locally without transmitting it anywhere: "
        "estimates entropy in bits, scores strength from 0 (very weak) to "
        "5 (very strong), detects common weak patterns and returns actionable "
        "feedback. The password is never logged, cached or persisted."
    ),
)
async def password_strength(
    payload: PasswordStrengthRequest,
    service: ToolboxService = Depends(get_toolbox_service),
) -> dict[str, Any]:
    return service.password_strength(payload.password)


# ── Unicode Inspector ─────────────────────────────────────────────────────────

@router.post(
    "/unicode/inspect",
    response_model=UnicodeInspectResponse,
    tags=["Data & Encoding"],
    summary="Inspect Unicode characters",
    description=(
        "Analyzes each character in the supplied text: codepoint, Unicode "
        "name, general category, script, block, bidirectional class, and "
        "numeric/alphabetic/whitespace/control classification. Useful for "
        "detecting homograph attacks, invisible characters and mixed-script "
        "content. Fully local — no external lookups."
    ),
)
async def unicode_inspect(
    payload: UnicodeInspectRequest,
    service: ToolboxService = Depends(get_toolbox_service),
) -> dict[str, Any]:
    return service.unicode_inspect(payload.text)
