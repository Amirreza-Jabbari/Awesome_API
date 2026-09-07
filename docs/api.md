# API Reference

All endpoints are versioned under `/api/v1`. Interactive documentation is available at `/docs` (Swagger UI) and `/redoc`.

## Table of Contents
- [Conventions](#conventions)
- [System Endpoints](#system-endpoints)
- [Email](#email)
- [Domain & DNS](#domain--dns)
- [IP & Network](#ip--network)
- [Web Analysis](#web-analysis)
- [Web Security](#web-security)
- [Web & HTTP](#web--http)
- [Data & Encoding](#data--encoding)
- [Developer Tools](#developer-tools)
- [Validation & Text](#validation--text)
- [Files & Metadata](#files--metadata)
- [Time & Date](#time--date)
- [cURL Examples](#curl-examples)

---

## Conventions

**Request body.** Most utility endpoints are `POST` endpoints expecting a JSON body. The browser-rendered Design System Extractor is a `GET` endpoint with a `url` query parameter.

**Response.** Success returns the documented JSON object. Errors always use a uniform envelope:
```json
{
  "error": {
    "code": "INVALID_EMAIL",
    "message": "The supplied email address is invalid."
  }
}
```

**Error codes.** 
- Validation problems return `4xx` (`VALIDATION_ERROR`, `INVALID_DOMAIN`, `INVALID_URL`, `SSRF_BLOCKED`, ...). 
- Provider failures map to `502/503/504` (`PROVIDER_UNAVAILABLE`, `WHOIS_UNAVAILABLE`, `DNS_TIMEOUT`, ...). 
- `429 RATE_LIMITED` when the per-IP limit is exceeded. 
- `413 RESOURCE_LIMIT` for size/length caps.
- Image tooling: `422 IMAGE_PROCESSING_ERROR`, `IMAGE_FORMAT_UNSUPPORTED`, `IMAGE_FEATURE_DISABLED`; `504 IMAGE_TIMEOUT` for processing that exceeds its time budget.

---

## System Endpoints

| Method | Path       | Description                                    |
| ------ | ---------- | ---------------------------------------------- |
| GET    | `/health`  | Liveness probe (`{"status":"healthy",...}`)    |
| GET    | `/ready`   | Readiness probe (DNS + cache availability)     |
| GET    | `/version` | Name, version, environment                     |
| GET    | `/metrics` | Prometheus metrics (only when `METRICS_ENABLED=true`) |

---

## Email

Endpoints for email validation, header inspection and mail-domain analysis.

### Disposable Email Checker
`POST /api/v1/email/disposable-check`

```json
{ "email": "test@example.com" }
```
```json
{ "email": "test@example.com", "domain": "example.com", "is_disposable": false }
```
Detects known disposable-email hosts, including subdomains of listed hosts. Case and IDN are normalized. Errors: `INVALID_EMAIL`.

### Email Validation
`POST /api/v1/email/validate`

```json
{ "email": "info@example.com" }
```
Syntax-level validation (not mailbox existence). Returns `domain`, `local_part`, `is_valid`, `is_disposable`, `is_public`, `mx_exists`. IDN domains are normalized.

### Email Header Analyzer
`POST /api/v1/email/analyze-headers`

```json
{
  "headers": "Received: from mail.example.com ...\nMessage-ID: <123@example.com>\nAuthentication-Results: spf=pass"
}
```
```json
{
  "message_id": "123@example.com",
  "from": "sender@example.com",
  "to": "recipient@example.com",
  "authentication": { "spf": "pass", "dkim": "none", "dmarc": "none" },
  "hops": 1
}
```
Parses raw RFC-style email headers and returns sender/recipient metadata, Message-ID, Received hops and SPF/DKIM/DMARC results found in Authentication-Results headers. It does not inspect message bodies or contact external mail servers.

### Email Domain Analyzer
`POST /api/v1/email/analyze-domain`

```json
{ "domain": "gmail.com" }
```
```json
{
  "domain": "gmail.com",
  "has_mx": true,
  "mx_records": [ { "priority": 10, "host": "gmail-smtp-in.l.google.com" } ],
  "spf_record": "v=spf1 redirect=_spf.google.com",
  "spf_valid": true,
  "dmarc_record": "v=DMARC1; p=none; rua=mailto:dmarc@google.com",
  "dmarc_policy": "none",
  "dmarc_pct": null,
  "is_disposable": false,
  "is_free_provider": true,
  "mail_provider": "Google Workspace / Gmail",
  "has_dmarc": true,
  "has_spf": true
}
```
Inspects a domain's email infrastructure: MX records, SPF record validity, DMARC policy and percentage, disposable/free-provider classification and inferred mail provider. Uses standard DNS lookups only — no paid or key-required services.

---

## Domain & DNS

Domain and DNS lookups: records, registration data, mail-exchange and DNSSEC validation.

### DNS Lookup
`POST /api/v1/dns/lookup`

```json
{ "domain": "example.com", "record_types": ["A", "AAAA", "MX"] }
```
`record_types` is optional (defaults to A/AAAA/MX/NS/SOA/TXT/CNAME). Response lists records with `record_type`, `value`, optional `priority`/`ttl` and SOA-specific fields.

### Domain Lookup
`POST /api/v1/domain/lookup`

```json
{ "domain": "example.com" }
```
Aggregates RDAP/WHOIS registration data, DNS signals, MX-provider/hosting detection and IP intelligence:
- `available`: `true` when unregistered, `false` when registered, `null` when unavailable.
- `creation_date`/`expiration_date`/`updated_date`: Unix timestamps (seconds).
- `registrar`, `domain_status`, `age_days`, `has_mx`, `mx_provider`, `is_parked`.
- `is_free_email_provider`, `is_disposable_email_domain`, `risky_tld`, `hosting_provider`, `country`, `is_custom_domain`.
- `is_malicious`: `true` when the host (or one of its subdomains) appears on the malicious/abusive hosts blocklist (`data/malicious_hosts.txt`, a large machine-generated spam/abusive blocklist loaded at startup). Exact and suffix matching is applied (listing `example.com` also flags `sub.example.com`). Heuristic signal for classification only, never authoritative policy.
- `ip`: the resolved native A record, when present.

### MX Lookup
`POST /api/v1/mx/lookup`

```json
{ "domain": "example.com" }
```
```json
{
  "domain": "example.com",
  "records": [ { "priority": 10, "value": "mx.example.net" } ]
}
```

### WHOIS
`POST /api/v1/whois/lookup`

```json
{ "domain": "example.com" }
```
Registry data via RDAP first, falling back to legacy WHOIS. Returns `registrar`, `registrar_url`, `whois_server`, `creation_date`/`expiration_date`/`updated_date` (Unix timestamps), `name_servers`, `dnssec`, `status`, `source` (`rdap`|`whois`). Errors: `WHOIS_UNAVAILABLE`; `INVALID_DOMAIN`.

### DNSSEC Validator
`POST /api/v1/dnssec/validate`

```json
{ "domain": "cloudflare.com" }
```
```json
{
  "domain": "cloudflare.com",
  "dnssec_enabled": true,
  "has_dnskey": true,
  "has_ds": true,
  "has_rrsig": true,
  "chain_valid": true,
  "records": [
    { "record_type": "DNSKEY", "flags": 257, "protocol": 3, "algorithm": 13, "value": "257 3 13 mdssw..." },
    { "record_type": "DS", "key_tag": 2371, "algorithm": 13, "digest_type": 2, "value": "2371 13 2 0x08..." }
  ],
  "error": null
}
```
Queries DNSKEY, DS and RRSIG records for a domain using the shared DNS provider and reports whether DNSSEC is enabled, whether the DS→DNSKEY chain is consistent, and lists the raw DNSSEC records. No external lookup service required.

---

## IP & Network

IP/URL intelligence and TCP port checks.

### IP Lookup
`POST /api/v1/ip/lookup`

```json
{ "ip": "8.8.8.8" }
```
Returns `ip_version`, `is_valid`, `is_private`, `is_loopback`, `is_multicast`, `is_bogon`, plus GeoIP/network/intelligence fields (`country`, `city`, `asn`, `route`, `abuse_email`, `is_datacenter`, `is_tor`, `is_vpn`, ...). Private/loopback/reserved addresses are never sent to external providers.

### URL Lookup
`POST /api/v1/url/lookup`

```json
{ "url": "example.com" }
```
Normalizes schemeless URLs to HTTPS and resolves the host (DNS + optional IP intelligence). **This endpoint never makes outbound HTTP requests to the target** and performs no content fetching. Literal IPs and reserved ranges such as `localhost`/`127.0.0.1`/metadata are rejected (`INVALID_URL`/`SSRF_BLOCKED`).

### Port Status Checker
`POST /api/v1/ports/check`

```json
{ "target": "8.8.8.8", "ports": [80, 443, 8080] }
```
```json
{
  "target": "8.8.8.8",
  "results": [
    { "port": 80, "status": "closed" },
    { "port": 443, "status": "open" },
    { "port": 8080, "status": "filtered" }
  ]
}
```
Checks a bounded list of TCP ports on a **public IP/hostname only**. Private, loopback, link-local, multicast, reserved, CGNAT and metadata targets are strictly blocked. The service connects to validated public addresses directly rather than trusting arbitrary internal DNS destinations.

---

## Web Analysis

Webpage metadata, user-agent parsing, SEO/robots/sitemap and link-integrity analysis.

### Webpage Metadata
`POST /api/v1/webpage/lookup`

```json
{ "url": "https://example.com" }
```
Fetches an HTML page (with strict SSRF protection, size/timeout limits and redirect validation, JS never executed) and returns `page_title`, `page_description`, `meta_tags`, `favicon`, plus `url`, `domain`, `url_path`, `url_parameters` and `final_url`. HTML-only: non-HTML bodies are reported without parsing. Errors: `SSRF_BLOCKED`, `RESOURCE_LIMIT`, `PROVIDER_TIMEOUT`, `PROVIDER_UNAVAILABLE`.

### User-Agent Parser
`POST /api/v1/user-agent/parse`

```json
{
  "useragent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.89 Safari/537.36"
}
```
Returns `browser_family`/`browser_version`, `os_family`/`os_version`, `device_family`/`device_brand`/`device_model`/`device_type`, `is_valid`, and `invalid_reason`. Note the request field is `useragent` (no hyphen).

### robots.txt Analyzer
`POST /api/v1/robots/analyze`

```json
{ "url": "https://example.com" }
```
```json
{
  "url": "https://example.com/robots.txt",
  "rules": [
    { "user_agent": "*", "allow": ["/"], "disallow": ["/private/"] }
  ],
  "sitemaps": ["https://example.com/sitemap.xml"]
}
```
Retrieves and parses robots.txt using the same secure web fetcher. It exposes user-agent allow/disallow rules and Sitemap declarations.

### Sitemap Analyzer
`POST /api/v1/sitemap/analyze`

```json
{ "url": "https://example.com/sitemap.xml" }
```
```json
{
  "url": "https://example.com/sitemap.xml",
  "type": "urlset",
  "urls": [
    { "loc": "https://example.com/page1", "lastmod": "2023-01-01" }
  ]
}
```
Parses XML sitemap files and sitemap indexes, returning URLs, last-modified values and child sitemap locations. XML is parsed as data; no scripts are executed.

### Open Graph Analyzer
`POST /api/v1/opengraph/analyze`

```json
{ "url": "https://example.com" }
```
```json
{
  "url": "https://example.com",
  "title": "Example Domain",
  "description": "This domain is for use in illustrative examples...",
  "image": "https://example.com/image.png",
  "site_name": "Example"
}
```
Extracts `og:*` metadata, including title, description, image, canonical URL and site name, while reusing the existing secure HTML fetch path.

### Website Technology Detector
`POST /api/v1/tech-detect`

```json
{ "url": "https://example.com" }
```
```json
{
  "url": "https://example.com",
  "status_code": 200,
  "server": "nginx",
  "powered_by": "PHP/8.2.0",
  "technologies": [
    { "name": "Nginx", "category": "server", "confidence": "high", "evidence": "Server header: nginx" },
    { "name": "PHP", "category": "language", "confidence": "high", "evidence": "X-Powered-By: PHP/8.2.0" },
    { "name": "WordPress", "category": "cms", "confidence": "high", "evidence": "wp-content or wp-includes found" },
    { "name": "Google Analytics", "category": "analytics", "confidence": "high", "evidence": "Google Analytics/tracking found" }
  ]
}
```
Fetches a live URL through the shared SSRF-hardened web fetcher and identifies technologies powering the site — CMS, framework, server, CDN, analytics, fonts, hosting platform — using HTTP headers and HTML content fingerprinting. Purely heuristic; no third-party service is queried.

### Redirect Analyzer
`POST /api/v1/redirect/analyze`

```json
{ "url": "http://example.com", "max_hops": 10 }
```
```json
{
  "url": "http://example.com",
  "final_url": "https://www.example.com/",
  "hops": [
    { "url": "http://example.com", "status_code": 301, "location": "https://example.com/", "redirect_type": "permanent" },
    { "url": "https://example.com/", "status_code": 301, "location": "https://www.example.com/", "redirect_type": "permanent" },
    { "url": "https://www.example.com/", "status_code": 200, "location": null, "redirect_type": null }
  ],
  "total_hops": 2,
  "is_loop": false,
  "has_https_redirect": true,
  "has_www_redirect": true
}
```
Follows the full redirect chain safely through the secure web fetcher, reporting each hop's status code and Location header. Identifies redirect loops, HTTP→HTTPS upgrades and www↔non-www redirects. Useful for SEO audits and link-integrity checks.

### Canonical URL Checker
`POST /api/v1/canonical/check`

```json
{ "url": "https://example.com" }
```
```json
{
  "url": "https://example.com",
  "final_url": "https://example.com",
  "canonical_url": "https://example.com/",
  "has_canonical": true,
  "is_self_referencing": true,
  "is_valid_canonical": null,
  "status_code": 200,
  "rel_canonical_header": null
}
```
Fetches a page and extracts its canonical URL from the HTML `<link rel="canonical">` tag or an HTTP `Link: rel="canonical"` header. Reports whether a canonical is present, whether it self-references, and the final URL after redirects. Essential for SEO duplicate-content audits.

---

## Web Security

Security-focused analysis: tokens, headers and TLS certificates.

### JWT Inspector
`POST /api/v1/jwt/inspect`

```json
{ "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" }
```
```json
{
  "header": { "alg": "HS256", "typ": "JWT" },
  "payload": { "sub": "1234567890", "name": "John Doe", "iat": 1516239022 },
  "signature_present": true,
  "is_expired": false
}
```
Decodes the JWT header and payload locally. It reports `alg`, `typ`, standard claims, signature presence and expiration state. **It does not verify the signature and never needs the signing secret.**

### JWT Generator
`POST /api/v1/jwt/generate`

```json
{
  "secret": "correct-horse-battery-staple-with-extra-entropy",
  "algorithm": "HS256",
  "payload": { "sub": "1234567890", "name": "John Doe", "role": "admin" },
  "expires_in": 3600,
  "issuer": "my-app",
  "audience": "my-clients"
}
```
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwicm9sZSI6ImFkbWluIiwiaXNzIjoibXktYXBwIiwiYXVkIjoibXktY2xpZW50cyIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoxNzAwMDAzNjAwfQ.IqY...",
  "token_type": "JWT",
  "algorithm": "HS256",
  "header": { "alg": "HS256", "typ": "JWT" },
  "payload": { "sub": "1234567890", "name": "John Doe", "role": "admin", "iss": "my-app", "aud": "my-clients", "iat": 1700000000, "exp": 1700003600 },
  "issued_at": 1700000000,
  "expires_at": 1700003600,
  "expires_in": 3600
}
```
Signs a JWT locally with HS256/HS384/HS512 using a supplied secret. `iat` is set to the current time and `exp = iat + expires_in`; optional `issuer`, `subject`, `audience`, `token_id` and extra `headers` are supported. The secret must be reasonably long (keys below the RFC 7518 minimum length for the algorithm are rejected with `VALIDATION_ERROR`). The token is returned once and never logged or persisted.

### HTTP Headers Analyzer
`POST /api/v1/http-headers/analyze`

```json
{
  "headers": {
    "content-type": "text/html; charset=utf-8",
    "x-frame-options": "DENY",
    "cache-control": "no-cache"
  }
}
```
```json
{
  "security": { "x-frame-options": "present", "strict-transport-security": "missing" },
  "cache": { "cache-control": "no-cache" },
  "content": { "content-type": "text/html; charset=utf-8" }
}
```
Analyzes a supplied response-header map locally, grouping security, cache, CORS, server and content signals. No network request is made.

### Security Headers Checker
`POST /api/v1/security-headers/check`

```json
{ "url": "https://example.com" }
```
```json
{
  "url": "https://example.com",
  "score": 85,
  "headers": {
    "strict-transport-security": "present",
    "content-security-policy": "missing",
    "x-content-type-options": "present"
  }
}
```
Fetches a live HTTPS/HTTP target through the existing SSRF-hardened webpage fetcher and checks CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy and X-Frame-Options. It returns a transparent presence score, not a claim of complete security.

### SSL/TLS Certificate Lookup
`POST /api/v1/tls/lookup`

```json
{ "host": "example.com", "port": 443 }
```
```json
{
  "host": "example.com",
  "port": 443,
  "subject": "CN=example.com",
  "issuer": "CN=DigiCert Inc, O=DigiCert Inc, C=US",
  "valid_from": 1672531200,
  "valid_to": 1704067200,
  "sans": ["example.com", "www.example.com"],
  "fingerprint_sha256": "ab:cd:ef:..."
}
```
Connects to a public TLS target and returns certificate subject, issuer, serial, validity, SANs and SHA-256 fingerprint. Certificate inspection does not require a provider API key.

---

## Data & Encoding

Hashing, encoding/decoding, identifiers and text/code data utilities.

### Hash Generator
`POST /api/v1/hash/generate`

```json
{ "text": "hello world", "algorithm": "sha256", "encoding": "utf-8" }
```
```json
{
  "algorithm": "sha256",
  "encoding": "utf-8",
  "hash": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
}
```
Supports MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, BLAKE2b and BLAKE2s. Input may be UTF-8 text, hex bytes or Base64 bytes. MD5/SHA-1 are retained for compatibility and identification, not recommended for new security designs.

### Hash Identifier
`POST /api/v1/hash/identify`

```json
{ "hash": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9" }
```
```json
{
  "hash": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
  "candidates": [
    { "algorithm": "SHA-256", "confidence": "high", "length": 64 },
    { "algorithm": "SHA3-256", "confidence": "medium", "length": 64 }
  ]
}
```
Uses digest length and character encoding to produce **heuristic** candidates. It cannot prove which algorithm produced an arbitrary hash.

### Base64 Encoder / Decoder
`POST /api/v1/base64`

```json
{ "mode": "encode", "text": "hello world", "encoding": "utf-8" }
```
```json
{ "mode": "encode", "encoding": "utf-8", "result": "aGVsbG8gd29ybGQ=" }
```
Use `mode=encode|decode` and `encoding=utf-8|hex`. Hex input/output makes binary payloads representable without requiring a file upload.

### URL Encoder / Decoder
`POST /api/v1/url/codec`

```json
{ "mode": "encode", "text": "hello world & friends", "component": true }
```
```json
{ "mode": "encode", "component": true, "result": "hello%20world%20%26%20friends" }
```
Percent-encodes or decodes a URL component. Set `component=false` when encoding a larger URL while preserving common URL delimiters.

### HTML Entity Encoder / Decoder
`POST /api/v1/html/entities`

```json
{ "mode": "encode", "text": "<script>alert('xss')</script>" }
```
```json
{ "mode": "encode", "result": "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;" }
```
Uses Python's standards-based HTML escaping/unescaping implementation.

### UUID Generator / Validator
`POST /api/v1/uuid/generate` and `POST /api/v1/uuid/validate`

**Generate:**
```json
{ "version": 4 }
```
```json
{ "uuid": "123e4567-e89b-12d3-a456-426614174000", "version": 4 }
```
**Validate:**
```json
{ "uuid": "123e4567-e89b-12d3-a456-426614174000" }
```
```json
{ "is_valid": true, "version": 4, "variant": "RFC 4122" }
```
Generates UUID versions 1, 3, 4, 5 and 7. Versions 3/5 accept built-in namespace names (`dns`, `url`, `oid`, `x500`) or an explicit namespace UUID.

### ULID Generator / Validator
`POST /api/v1/ulid/generate` and `POST /api/v1/ulid/validate`

**Generate:**
```json
{}
```
```json
{ "ulid": "01ARZ3NDEKTSV4RRFFQ69G5FAV" }
```
**Validate:**
```json
{ "ulid": "01ARZ3NDEKTSV4RRFFQ69G5FAV" }
```
```json
{ "is_valid": true, "timestamp_ms": 1469918176385, "timestamp_iso": "2016-07-30T22:36:16.385Z" }
```
Generates canonical 26-character ULIDs and decodes their embedded millisecond timestamp during validation.

### JSON Formatter & Validator
`POST /api/v1/json`

```json
{ "mode": "pretty", "json": "{\"key\":\"value\"}" }
```
```json
{
  "is_valid": true,
  "mode": "pretty",
  "result": "{\n  \"key\": \"value\"\n}"
}
```
Supports `validate`, `pretty` and `minify` modes and reports JSON syntax line/column information without executing embedded content.

### JSON Diff
`POST /api/v1/json/diff`

```json
{ "document_a": "{\"a\": 1, \"b\": 2}", "document_b": "{\"a\": 1, \"c\": 3}" }
```
```json
{
  "equal": false,
  "added": 1,
  "removed": 1,
  "modified": 0,
  "total_changes": 2,
  "changes": [
    { "path": "/b", "operation": "removed", "before": 2 },
    { "path": "/c", "operation": "added", "after": 3 }
  ]
}
```
Compares two JSON documents recursively and reports structural differences with RFC 6901 JSON-Pointer paths. `added`/`removed`/`modified` are operation counts; `total_changes` is their sum. Arrays are diffed by position and paths use JSON-Pointer with array indices (`/items/0`). `before` is present on removed/modified entries, `after` on added/modified entries.

### JSON Patch
`POST /api/v1/json/patch`

```json
{ "document_a": "{\"name\": \"x\", \"tags\": [\"a\"]}", "document_b": "{\"name\": \"y\", \"tags\": [\"a\", \"b\"]}" }
```
```json
{
  "patch": [
    { "op": "replace", "path": "/name", "value": "y" },
    { "op": "add", "path": "/tags/1", "value": "b" }
  ],
  "operation_count": 2,
  "transformable": true
}
```
Generates an RFC 6902 JSON Patch (add/remove/replace operations) that transforms `document_a` into `document_b`. `transformable` indicates whether applying the patch to `document_a` reproduces `document_b` when re-serialized. The patch can be applied with any standards-compliant JSON Patch library.

### YAML Converter
`POST /api/v1/yaml/convert`

```json
{ "direction": "json_to_yaml", "input": "{\"name\": \"demo\", \"enabled\": true}" }
```
```json
{
  "valid": true,
  "direction": "json_to_yaml",
  "output": "name: demo\nenabled: true\n",
  "value": { "name": "demo", "enabled": true },
  "type": "object",
  "error": null
}
```
Converts between YAML and JSON. Use `direction=yaml_to_json` to parse a YAML document into JSON, or `json_to_yaml` to serialize JSON into YAML. Uses a standards-compliant YAML 1.1 parser; aliases and complex keys are handled safely. `error` is `null` on success.

### XML Converter
`POST /api/v1/xml/convert`

```json
{ "direction": "json_to_xml", "input": "{\"id\": 5, \"@attr\": \"1\"}", "root_name": "root" }
```
```json
{ "valid": true, "direction": "json_to_xml", "root": "root", "output": "<root attr=\"1\"><id>5</id></root>", "error": null }
```
Converts between JSON and XML using `defusedxml`, so entity-expansion (billion-laughs) and external-entity attacks are blocked. For `json_to_xml`, keys prefixed with `@` become attributes and `#text` becomes the element's text; `root_name` overrides the implicit root. For `xml_to_json`, repeated child elements are grouped into arrays, text is exposed under `#text`, and the parsed object is returned under `value`. Invalid input returns `VALIDATION_ERROR`.

### Unicode Inspector
`POST /api/v1/unicode/inspect`

```json
{ "text": "Héllo" }
```
```json
{
  "input": "Héllo",
  "length": 5,
  "total_codepoints": 5,
  "scripts": ["Latin"],
  "categories": ["Ll", "Lu", "Lo"],
  "characters": [
    { "char": "H", "codepoint": "U+0048", "name": "LATIN CAPITAL LETTER H", "category": "Lu", "category_name": "Letter, uppercase", "script": "Latin", "block": "U+0041", "bidirectional": "L", "is_alphabetic": true, "is_numeric": false, "is_whitespace": false, "is_control": false, "decimal_value": null },
    { "char": "é", "codepoint": "U+00E9", "name": "LATIN SMALL LETTER E WITH ACUTE", "category": "Ll", "category_name": "Letter, lowercase", "script": "Latin", "block": "U+00C0", "bidirectional": "L", "is_alphabetic": true, "is_numeric": false, "is_whitespace": false, "is_control": false, "decimal_value": null }
  ]
}
```
Analyzes each character: codepoint, Unicode name, general category, script, block, bidirectional class, and numeric/alphabetic/whitespace/control classification. Useful for detecting homograph attacks, invisible characters and mixed-script content. Fully local — no external lookups.

---

## Web & HTTP

HTTP request building/execution, inspection, curl/header generation and URL parsing. Live fetches are SSRF-hardened and size/timeout-capped; credentials are never logged or persisted.

### HTTP Request Builder / Executor
`POST /api/v1/http/request`

```json
{
  "request": {
    "method": "GET",
    "url": "https://example.com/api",
    "query": [ { "name": "q", "value": "hello world" } ],
    "headers": { "Accept": "application/json" }
  },
  "execute": false
}
```
```json
{
  "mode": "build",
  "method": "GET",
  "url": "https://example.com/api?q=hello+world",
  "raw_query": "q=hello+world",
  "headers": { "Accept": "application/json" },
  "curl": "curl 'https://example.com/api?q=hello+world'",
  "ssrf_checked": false,
  "error": null
}
```
Builds a canonical HTTP request (normalized URL, URL-safe query string, body encoding for `text`/`raw`/`json`/`xml`/`form`/`binary`, optional Basic/Bearer authorization) and its curl equivalent. With `execute=true` the request is actually sent through the SSRF guard (private/loopback/metadata targets blocked, redirects re-validated, response capped); the response headers/body and final URL are returned with `mode: "execute"`. Literal credentials may be supplied but are never logged; `file://`/`gopher://` and other non-http(s) schemes are rejected.

### HTTP Inspector
`POST /api/v1/http/inspect`

```json
{ "url": "https://example.com/data.json", "method": "GET", "follow_redirects": false, "max_body_size": 2048 }
```
```json
{
  "valid": true,
  "url": "https://example.com/data.json",
  "status_code": 200,
  "reason": "OK",
  "headers": { "content-type": "application/json" },
  "cookies": [],
  "body_preview": "{\"ok\": true}",
  "body_size": 12,
  "content_type": "application/json",
  "charset": "utf-8",
  "is_json": true,
  "redirects": [],
  "error": null
}
```
Performs a live HTTP request and reports status, reason, headers, cookies, content type/charset, a truncated body preview, JSON detection and redirect history. The host is checked through the SSRF guard before connecting, on every redirect hop, and the final peer address is verified against the URL host (DNS-rebinding defense). Response size and total time are capped.

### curl Generator
`POST /api/v1/http/curl`

```json
{ "method": "POST", "url": "https://example.com/api", "body": "{\"a\":1}", "body_type": "json", "pretty": true, "follow_redirects": true, "compressed": true, "silent": true }
```
```json
{
  "command": "curl \\\n  -L \\\n  --compressed \\\n  -s \\\n  -X \\\n  POST \\\n  --data-raw \\\n  '{\"a\":1}' \\\n  'https://example.com/api'",
  "flags": ["-L", "--compressed", "-s", "-X", "POST"]
}
```
Renders a ready-to-paste curl command without any network I/O. Options: `pretty` (multi-line), `include_headers` (`-i`), `follow_redirects` (`-L`), `compressed` (`--compressed`), `silent` (`-s`). Body and header tokens are shell-quoted.

### Headers Generator
`POST /api/v1/http/headers`

```json
{ "headers": [ { "name": "X-Debug", "value": "1" } ], "style": "lowercase", "include_content_length": true }
```
```json
{
  "count": 1,
  "normalized": [ { "name": "x-debug", "value": "1" } ],
  "issues": [],
  "raw": "x-debug: 1\nContent-Length: 2\n"
}
```
Builds raw HTTP/1.1-style header lines from name/value pairs. `style` is `none` (as-is), `lowercase` or `uppercase`. Duplicate/case-colliding names are reported in `issues`. Optional computed `Content-Length` line. Pure local formatting — nothing is sent.

### URL Parser
`POST /api/v1/url/parse`

```json
{ "url": "https://u:p@example.com:8443/a?x=1&x=2&y=3#frag" }
```
```json
{
  "valid": true,
  "scheme": "https",
  "host": "example.com",
  "port": 8443,
  "path": "/a",
  "fragment": "frag",
  "query": [ { "name": "x", "value": "2" }, { "name": "y", "value": "3" } ],
  "params": { "x": "2", "y": "3" },
  "username": "u",
  "password": "p",
  "url_without_query": "https://u:p@example.com:8443/a#frag"
}
```
Splits a URL into scheme, host, port, path, fragment and query-string parameters — both as a paired list and as a dict (later duplicates win in the dict). Userinfo credentials, when present, are reported separately (executed requests reject them for security). `hostname` is returned without brackets for IPv6; `error` is `null` on success.

---

## Developer Tools

SQL formatting/minification/validation, SemVer analysis, changelog generation, color conversion and mock-data generation. All fully local.

### SQL Formatter
`POST /api/v1/sql/format`

```json
{ "sql": "select id,name from users where id=1", "keyword_case": "upper", "indent": 2, "strip_comments": true, "reindent": true }
```
```json
{
  "valid": true,
  "formatted": "SELECT id, name\nFROM users\nWHERE id = 1\n",
  "statement_count": 1,
  "issues": [],
  "error": null
}
```
Pretty-prints SQL statements with configurable keyword casing and indentation, optionally stripping comments. Pure text transformation — the statement is validated structurally before formatting.

### SQL Minifier
`POST /api/v1/sql/minify`

```json
{ "sql": "-- comment\nselect  1 /* inline */;", "keyword_case": "lower", "strip_comments": true }
```
```json
{
  "valid": true,
  "minified": "select 1    ;",
  "removed_comments": 2,
  "statement_count": 1,
  "original_length": 34,
  "minified_length": 14,
  "error": null
}
```
Compresses SQL by normalizing whitespace and optionally removing comments. Reports the number of comments removed and the original/minified length in characters.

### SQL Validator
`POST /api/v1/sql/validate`

```json
{ "sql": "SELECT * FROM users WHERE id = 1;" }
```
```json
{ "valid": true, "statement_count": 1, "errors": [], "warnings": [] }
```
Parses SQL and reports structural problems in `errors` (syntax/parse failures) and `warnings` (e.g. trivial conditional filters such as `WHERE 1=1`). `valid` is `true` only when there are no errors.

### SemVer Analyzer
`POST /api/v1/semver/analyze`

```json
{ "version": "1.2.3", "other": "1.3.0", "range": "^1.0.0" }
```
```json
{
  "valid": true,
  "core": "1.2.3",
  "major": 1,
  "minor": 2,
  "patch": 3,
  "prerelease": null,
  "build": null,
  "is_prerelease": false,
  "comparison": { "comparable": true, "other": "1.3.0", "value": -1, "is_breaking": false, "reason": null },
  "range_result": { "valid": true, "matches": true, "error": null }
}
```
Validates a SemVer 2.0.0 string and returns its components. When `other` is supplied, `comparison.value` is `-1` (main version is older), `0` (equal) or `1` (newer) relative to `other`, and `is_breaking` flags a major bump (or minor bump within `0.x`) between the two versions. When `range` is supplied, `range_result.matches` indicates whether the version satisfies the range (supports `*`, `x`, `~`, `^`, `||`, comparators).

### Changelog Generator
`POST /api/v1/changelog/generate`

```json
{
  "commits": [
    { "type": "feat", "description": "add widget API" },
    { "type": "fix", "description": "repair widget sort", "breaking": true },
    { "type": "perf", "description": "speed up widget rendering" }
  ],
  "version": "1.0.0",
  "date": "2026-09-05"
}
```
```json
{
  "markdown": "## 1.0.0 (2026-09-05)\n\n### Features\n- feat: add widget API\n\n### Bug Fixes\n- fix: repair widget sort\n\n### Performance\n- perf: speed up widget rendering\n\n### Breaking Changes\n- fix: repair widget sort\n",
  "sections": { "feat": ["- feat: add widget API"], "fix": [], "perf": ["- perf: speed up widget rendering"] },
  "counts": { "feat": 1, "fix": 1, "perf": 1 },
  "excluded": 0
}
```
Generates a Keep-a-Changelog–style markdown document from conventional commits. `sections` groups commits by raw type; breaking commits are pulled out of their type group into a `Breaking Changes` heading in the markdown. `title` produces an `# <title>` heading, `unreleased` renders the "Unreleased" section, and unparseable commits are counted in `excluded`.

### Color Converter
`POST /api/v1/color/convert`

```json
{ "color": "#ff0000", "from_format": "auto" }
```
```json
{
  "valid": true,
  "from_format": "hex",
  "hex": "#ff0000",
  "rgb": { "r": 255, "g": 0, "b": 0 },
  "rgba": { "r": 255, "g": 0, "b": 0, "a": 1.0 },
  "hsl": { "h": 0.0, "s": 100.0, "lightness": 50.0 },
  "hsv": { "h": 0.0, "s": 100.0, "v": 100.0 },
  "css": { "rgb": "rgb(255, 0, 0)", "rgba": "rgba(255, 0, 0, 1)", "hsl": "hsl(0, 100%, 50%)", "hex": "#ff0000" },
  "luminance": 0.2126,
  "contrast": null,
  "notes": [],
  "error": null
}
```
Accepts hex, `rgb()`/`rgba()`, `hsl()`/`hsla()`, `hsv()`/`hsva()` strings, named colors, and the CSS string itself can be inferred via `from_format: "auto"`. Returns the color in all formats, a computed WCAG luminance, and — when `background` is provided — the contrast ratio. HSL uses the `lightness` key. Invalid colors return `VALIDATION_ERROR`.

### Mock Data Generator (fields)
`POST /api/v1/mock/generate`

```json
{ "fields": [ { "name": "id", "type": "integer", "minimum": 1, "maximum": 999 }, { "name": "email", "type": "string", "format": "email" } ], "seed": 42 }
```
```json
{
  "value": { "id": 137, "email": "epyyngfb@example.com" },
  "json": "{\"id\": 137, \"email\": \"epyyngfb@example.com\"}",
  "type": "object",
  "node_count": 3,
  "truncated": false,
  "warning": null
}
```
Generates realistic mock JSON from a field list (`string`, `integer`, `number`, `boolean`, `null`, `object`, `array`, `enum`, `datetime`, `date`, `uuid`, `email`, `url`, `ipv4`, `ipv6`, `hostname`, names, `company`, `color`, `phone`) with constraints (`minimum`/`maximum`, `min_length`/`max_length`, `min_items`/`max_items`, `enum`, `nullable`). A `seed` makes output deterministic; `node_count`/`truncated` report generation size. Alternatively provide a JSON Schema via `schema` instead of `fields` (exactly one of the two is required).

### Mock Data Generator (OpenAPI)
`POST /api/v1/mock/openapi`

```json
{ "document": "openapi: 3.0.0\ninfo:\n  title: Demo\n  version: 1.0.0\npaths:\n  /pets:\n    get:\n      operationId: listPets\n      responses:\n        '200':\n          content:\n            application/json:\n              schema:\n                type: array\n                maxItems: 3\n                items:\n                  type: object\n                  properties:\n                    name:\n                      type: string\n", "path": "/pets", "method": "get", "seed": 7 }
```
```json
{
  "valid": true,
  "operation_id": "listPets",
  "path": "/pets",
  "method": "get",
  "status_code": 200,
  "content_type": "application/json",
  "content": [ { "name": "K2ZWeqhF" } ],
  "json": "[{\"name\": \"K2ZWeqhF\"}]\n",
  "matched_schema": "…/content/application~1json/schema",
  "error": null
}
```
Parses an OpenAPI 3.x document (YAML or JSON), selects an operation by path/method, and generates mock data for its `200` response schema using the same seeded generator. `max_array_length`/`max_depth` cap output; `seed` makes it deterministic. Unknown paths/methods return 400 with `error` set.

---

## Validation & Text

Password and text validation utilities.

### Password Generator
`POST /api/v1/password/generate`

```json
{
  "length": 16,
  "exclude_numbers": false,
  "exclude_special_chars": false,
  "min_upper": 1,
  "min_lower": 1,
  "min_numbers": 1,
  "min_specials": 1
}
```
```json
{ "random_password": "9X4emWnqsdnDee%N)R88" }
```
Cryptographically secure (`secrets`). At least one char from each enabled, required category is guaranteed. Passwords are never cached/logged/persisted. Errors: `RESOURCE_LIMIT` for infeasible configurations.

### Password Strength Analyzer
`POST /api/v1/password/strength`

```json
{ "password": "MyP@ssw0rd2024!" }
```
```json
{
  "score": 4,
  "entropy_bits": 97.5,
  "crack_time_display": "longer than the age of the universe",
  "has_uppercase": true,
  "has_lowercase": true,
  "has_numbers": true,
  "has_special": true,
  "has_unicode": false,
  "length": 15,
  "character_variety": 4,
  "common_pattern": false,
  "feedback": []
}
```
Evaluates a password locally without transmitting it anywhere: estimates entropy in bits, scores strength from 0 (very weak) to 5 (very strong), detects common weak patterns and returns actionable feedback. The password is never logged, cached or persisted.

### Phone Validation
`POST /api/v1/phone/validate`

```json
{ "number": "+14155552671", "country": null }
```
`country` (ISO-3166 alpha-2) is optional and helps parse national numbers. Distinguishes `is_valid` (numbering-plan rules) from `is_possible`. Returns formatted forms (`format_national`, `format_international`, `format_e164`, `format_rfc3966`), `country_code`, `location`, `timezones`, `line_type`, `is_mobile`, `reason`.

### Regex Tester
`POST /api/v1/regex`

```json
{ "pattern": "^[a-z]+$", "text": "hello", "flags": "i" }
```
```json
{
  "is_valid": true,
  "pattern": "^[a-z]+$",
  "flags": "i",
  "matches": [
    { "match": "hello", "start": 0, "end": 5, "groups": {} }
  ]
}
```
Compiles a supplied Python regular expression, returns matches, offsets, capture groups and named groups, or a precise compile error. Supported flags are `i`, `m`, `s`, `x` and `a`.

---

## Files & Metadata

File-type and image metadata extraction.

### File Metadata Extractor
`POST /api/v1/file/metadata`

```json
{
  "data": "/9j/4AAQSkZJRgABAQAAAQABAAD/...",
  "filename": "photo.jpg"
}
```
```json
{
  "mime_type": "image/jpeg",
  "extension": ".jpg",
  "size_bytes": 102457,
  "magic_match": true,
  "description": "JPEG image"
}
```
Detects the MIME type of Base64-encoded file content using magic-byte sniffing. Returns detected type, guessed extension, decoded size and textual description. Optionally accepts a filename for extension hints. No file is uploaded or persisted.

### Content Type Detector
`POST /api/v1/content-type/detect`

```json
{ "url": "https://example.com/file.pdf", "check_body": true }
```
```json
{
  "url": "https://example.com/file.pdf",
  "declared_type": "application/pdf",
  "charset": null,
  "mime_type": "application/pdf",
  "body_sniffed_type": "application/pdf",
  "is_html": false,
  "is_json": false,
  "is_xml": false,
  "is_binary": true
}
```
Fetches a URL through the secure web fetcher and reports the declared Content-Type header, charset, and — when `check_body=true` — the body-sniffed MIME type from magic bytes. Useful for debugging misconfigured servers and verifying content negotiation.

### Image Metadata Analyzer
`POST /api/v1/image/metadata`

```json
{
  "data": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB...",
  "filename": "screenshot.png"
}
```
```json
{
  "format": "PNG",
  "width": 1920,
  "height": 1080,
  "mode": "RGB",
  "has_exif": false,
  "exif": {},
  "icc_profile": null,
  "is_animated": false,
  "frame_count": 1,
  "error": null
}
```
Decodes Base64-encoded image data and extracts dimensions, format, color mode, EXIF tags (camera, date, GPS), ICC color profile and animation frame count using Pillow. Supports JPEG, PNG, GIF, WEBP, TIFF, BMP and more. No external service is queried.

---

## Image Processing

Local, in-memory image conversion: raster re-encoding, image→PDF, PDF → per-page
rasterization (ZIP), PSD flattening, HEIC/HEIF decode, target-size compression,
canvas resizing and optional AI background removal. All uploads are processed in
worker threads under a hard timeout and concurrency semaphore; outputs are
re-encoded and **never carry EXIF/location metadata**, and nothing is stored on
the server between requests.

### Image Formats & Capabilities
`GET /api/v1/image/formats`

```json
{
  "read_formats": [".avif", ".bmp", ".gif", ".heic", ".heif", ...],
  "write_formats": ["avif", "bmp", "ico", "jpeg", "pdf", "png", "tiff", "webp"],
  "pdf_presets": ["a4-auto", "a4-landscape", "a4-portrait", "letter-auto", ...],
  "pdf_scale_modes": ["fill", "fit"],
  "pdf_quality_presets": { "high": 220, "medium": 150, "small": 96, "ultra": 300 },
  "background_removal": { "enabled": false, "installed": false, "model": "u2net" },
  "limits": {
    "max_input_bytes": 7500000,
    "max_pixels": 40000000,
    "max_output_bytes": 15000000,
    "max_pdf_pages": 50,
    "max_pdf_dpi": 300,
    "max_target_size_kb": 4000,
    "max_concurrent": 2
  }
}
```
Reports the raster formats the deployment can read/write, available PDF presets
and quality levels, whether AI background removal is enabled, and the enforced
processing limits.

### Image Converter
`POST /api/v1/image/convert` — `multipart/form-data`

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `file` | file | — | One raster image (JPEG/PNG/WEBP/AVIF/TIFF/BMP/GIF/ICO/HEIC/HEIF/PSD) |
| `format` | string | — | `jpeg`, `png`, `webp`, `avif`, `ico`, `tiff`, `bmp` or `pdf` |
| `quality` | int | `85` | Encoding quality, `1..100` (raster outputs) |
| `width` | int | — | Optional downscale target width in pixels |
| `target_size_kb` | int | — | Target output size in KB (JPEG/WebP/AVIF) |
| `pdf_preset` | string | — | e.g. `a4-auto`, `letter-portrait`, `mobile-portrait`, `original` |
| `pdf_scale` | string | `fit` | `fit` or `fill` |
| `pdf_margin_mm` | number | — | PDF margin in millimetres (defaults to the preset) |
| `pdf_paginate` | bool | `false` | Split a tall image across PDF pages |
| `pdf_quality` | string | `high` | `small`, `medium`, `high` or `ultra` |

Returns the converted file bytes with `Content-Disposition`, `X-Image-Format`,
`X-Image-Bytes`, `X-Image-Width` and `X-Image-Height` headers. `target_size_kb`
binary-searches the best JPEG/WebP/AVIF quality under the byte budget. PDF inputs
are handled by `/api/v1/image/rasterize` instead.

```bash
curl -X POST http://localhost:8000/api/v1/image/convert \
  -F "file=@photo.png" -F "format=jpeg" -F "width=800"
```

### Image Resizer
`POST /api/v1/image/resize` — `multipart/form-data`

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `file` | file | — | Raster image |
| `width` | int | — | Target width (aspect preserved) |
| `canvas_width` / `canvas_height` | int | — | Both required together for canvas placement |
| `mode` | string | `fit` | `fit` or `fill` placement on the canvas |
| `margin_mm` | number | `0` | Canvas margin in millimetres |
| `auto_rotate` | bool | `false` | Rotate the canvas to match image orientation |
| `output_format` | string | `png` | `png`, `jpeg`, `webp`, `avif` or `bmp` |

Shrinks to a target `width` (LANCZOS, aspect preserved) and/or places the image
on a white canvas. Returns re-encoded bytes with the same `X-Image-*` headers.

### PDF Rasterizer
`POST /api/v1/image/rasterize` — `multipart/form-data`

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `file` | file | — | PDF document |
| `page_format` | string | `jpeg` | `jpeg` or `png` |
| `dpi` | int | `150` | Rendering DPI (at least 36; capped server-side) |

Renders each page into an image and returns a ZIP archive. Adds the
`X-Image-Pages` response header with the page count. Page count and total
output size are bounded by deployment limits.

### AI Background Removal
`POST /api/v1/image/background` — `multipart/form-data`

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `file` | file | — | Raster image |
| `output_format` | string | `png` | `png` or `avif` |

Runs rembg (`u2net`) locally and returns a transparent PNG/AVIF. Disabled unless
`IMAGE_BACKGROUND_REMOVAL_ENABLED=true` and the optional `[image-ai]` extra is
installed; otherwise responds `422 IMAGE_FEATURE_DISABLED`.

---

## Time & Date

Timestamp, timezone and cron-schedule utilities.

### Cron Expression Generator
`POST /api/v1/cron/generate`

```json
{ "schedule": "every day at 09:30" }
```
```json
{
  "valid": true,
  "error": null,
  "expression": "30 9 * * *",
  "description": "at 09:30 every day",
  "fields": {
    "minute": { "value": "30", "values": [30], "valid": true, "error": null },
    "hour": { "value": "9", "values": [9], "valid": true, "error": null },
    "day_of_month": { "value": "*", "values": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31], "valid": true, "error": null },
    "month": { "value": "*", "values": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12], "valid": true, "error": null },
    "day_of_week": { "value": "*", "values": [0, 1, 2, 3, 4, 5, 6], "valid": true, "error": null }
  }
}
```
Translates plain-English schedules (`every minute`, `every 5 minutes`, `every 6 hours`, `every day at 09:30`, `every weekday at 18:00`, `every monday at 08:15`, `every month on day 1 at 08:00`, `on january 1 at 09:00`, …) into 5-field cron expressions. The `fields` map lists each field's expanded values. Unrecognized schedules return `valid: false` with `error`.

### Cron Expression Parser
`POST /api/v1/cron/parse`

```json
{ "expression": "0 9 * * *", "count": 5, "reference_timestamp": 1757088000 }
```
```json
{
  "valid": true,
  "error": null,
  "fields": { "minute": { "value": "0", "values": [0], "valid": true, "error": null }, "hour": { "value": "9", "values": [9], "valid": true, "error": null }, "day_of_month": { "value": "*", "values": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31], "valid": true, "error": null }, "month": { "value": "*", "values": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12], "valid": true, "error": null }, "day_of_week": { "value": "*", "values": [0, 1, 2, 3, 4, 5, 6], "valid": true, "error": null } },
  "next_count": 5,
  "next_times": [ "2025-09-06T09:00:00+00:00", "2025-09-07T09:00:00+00:00", "2025-09-08T09:00:00+00:00", "2025-09-09T09:00:00+00:00", "2025-09-10T09:00:00+00:00" ]
}
```
Validates a 5-field cron expression (supports `*`, lists, ranges, steps, `L`, `W`, `#`) and expands each field to its resolved values. Computes the next `count` (1–100) trigger times as UTC ISO-8601 strings, optionally anchored to `reference_timestamp` for deterministic testing. Day-of-week names (`mon`–`sun`) are accepted.

### Timestamp Converter
`POST /api/v1/timestamp/convert`

```json
{ "unix": 1672531200 }
```
```json
{
  "unix": 1672531200,
  "iso": "2023-01-01T00:00:00Z",
  "timezone": "UTC",
  "readable": "Sunday, January 1, 2023 12:00:00 AM"
}
```
Converts Unix seconds or an ISO-8601 datetime into UTC and an IANA timezone. Exactly one input representation is required.

### Timezone Lookup
`POST /api/v1/timezone/lookup`

```json
{ "ip": "8.8.8.8" }
```
*(Alternatively: `{ "latitude": 40.7128, "longitude": -74.0060 }`)*
```json
{
  "query_type": "ip",
  "timezone": "America/New_York",
  "offset": "-05:00",
  "offset_dst": "-04:00",
  "abbreviation": "EST"
}
```
Accepts either an IP address or latitude/longitude. IP lookups reuse the existing IP/GeoIP service. Coordinate lookups use a no-key coordinate timezone source.

---

## cURL Examples

**Disposable email check:**
```bash
curl -X POST http://localhost:8000/api/v1/email/disposable-check \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com"}'
```

**Password generation:**
```bash
curl -X POST http://localhost:8000/api/v1/password/generate \
  -H "Content-Type: application/json" \
  -d '{"length":20}'
```

**DNS lookup:**
```bash
curl -X POST http://localhost:8000/api/v1/dns/lookup \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com","record_types":["A","MX"]}'
```

**Webpage metadata:**
```bash
curl -X POST http://localhost:8000/api/v1/webpage/lookup \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

**JWT Inspector:**
```bash
curl -X POST http://localhost:8000/api/v1/jwt/inspect \
  -H "Content-Type: application/json" \
  -d '{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}'
```

**Port Status Checker:**
```bash
curl -X POST http://localhost:8000/api/v1/ports/check \
  -H "Content-Type: application/json" \
  -d '{"target":"8.8.8.8","ports":[80,443]}'
```

**Website Technology Detector:**
```bash
curl -X POST http://localhost:8000/api/v1/tech-detect \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

**Redirect Analyzer:**
```bash
curl -X POST http://localhost:8000/api/v1/redirect/analyze \
  -H "Content-Type: application/json" \
  -d '{"url":"http://example.com"}'
```

**DNSSEC Validator:**
```bash
curl -X POST http://localhost:8000/api/v1/dnssec/validate \
  -H "Content-Type: application/json" \
  -d '{"domain":"cloudflare.com"}'
```

**Email Domain Analyzer:**
```bash
curl -X POST http://localhost:8000/api/v1/email/analyze-domain \
  -H "Content-Type: application/json" \
  -d '{"domain":"gmail.com"}'
```

**File Metadata Extractor:**
```bash
curl -X POST http://localhost:8000/api/v1/file/metadata \
  -H "Content-Type: application/json" \
  -d '{"data":"UEsDBBQACAgI...","filename":"archive.zip"}'
```

**Content Type Detector:**
```bash
curl -X POST http://localhost:8000/api/v1/content-type/detect \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com/file.pdf","check_body":true}'
```

**Canonical URL Checker:**
```bash
curl -X POST http://localhost:8000/api/v1/canonical/check \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

**Image Metadata Analyzer:**
```bash
curl -X POST http://localhost:8000/api/v1/image/metadata \
  -H "Content-Type: application/json" \
  -d '{"data":"iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB...","filename":"photo.png"}'
```

**Password Strength Analyzer:**
```bash
curl -X POST http://localhost:8000/api/v1/password/strength \
  -H "Content-Type: application/json" \
  -d '{"password":"MyP@ssw0rd2024!"}'
```

**Unicode Inspector:**
```bash
curl -X POST http://localhost:8000/api/v1/unicode/inspect \
  -H "Content-Type: application/json" \
  -d '{"text":"Héllo 👋"}'
```

**Cron Generator:**
```bash
curl -X POST http://localhost:8000/api/v1/cron/generate \
  -H "Content-Type: application/json" \
  -d '{"schedule":"every weekday at 18:00"}'
```

**HTTP Request Builder:**
```bash
curl -X POST http://localhost:8000/api/v1/http/request \
  -H "Content-Type: application/json" \
  -d '{"request":{"method":"POST","url":"https://example.com/api","body":"{\"a\":1}","body_type":"json"}}'
```

**SQL Formatter:**
```bash
curl -X POST http://localhost:8000/api/v1/sql/format \
  -H "Content-Type: application/json" \
  -d '{"sql":"select id,name from users where id=1","keyword_case":"upper"}'
```

**Mock Data Generator:**
```bash
curl -X POST http://localhost:8000/api/v1/mock/generate \
  -H "Content-Type: application/json" \
  -d '{"fields":[{"name":"id","type":"integer"},{"name":"email","type":"string","format":"email"}],"seed":42}'
```


---

# Production API behavior

## Error envelope

Expected framework and application exceptions use a stable envelope:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "The supplied input is invalid.",
    "request_id": "01J..."
  }
}
```

`details` may be present when it contains safe, non-sensitive diagnostic metadata. Stack traces, filesystem paths, credentials, authorization data and raw upstream failures are not returned.

Endpoint-level response models that intentionally return `valid: false` or an `error` field remain unchanged; these are semantic tool results rather than HTTP failures.

## Rate limiting

API requests are limited centrally. The policy is selected by endpoint class:

| Policy | Default/minute | Examples |
|---|---:|---|
| General | 60 | ordinary local utilities |
| Expensive | 20 | DNS, MX, WHOIS, domain and IP enrichment |
| Network | 15 | live HTTP/web analysis |
| Security | 30 | JWT, regex, password and SQL utilities |

Limits are configured through `RATE_LIMIT_*` environment variables. Successful API responses include `X-RateLimit-Limit`, `X-RateLimit-Remaining` and `X-RateLimit-Reset`. A rejected request returns HTTP `429` with `Retry-After`.

## Request and upstream limits

Central defaults include a 12 MB request body budget, a 10.5 MB JSON budget, an 8 KB URL budget, JSON depth/node budgets, and a 5 MB upstream response budget. Individual endpoint schemas may impose stricter limits.

## API versioning

The stable public API is mounted under `/api/v1`. The version boundary is isolated in `app/api/router.py`, so a future breaking API can be mounted as `/api/v2` without changing V1 routes.

## Metrics

When `METRICS_ENABLED=true`, Prometheus exposition is available at `/metrics`. The endpoint is intentionally excluded from the public OpenAPI operation count and does not expose request IDs, arbitrary URLs, query parameters or other high-cardinality user input.

## Health endpoints

- `/health` is a lightweight liveness probe.
- `/ready` reports readiness and safe dependency diagnostics. Optional dependencies do not become mandatory merely because they are configured for enrichment.
- `/version` reports application identity and version information without exposing secrets.

## SDK generation

Run:

```bash
make generate-sdk
```

The command regenerates `sdk/openapi.json`, a Python client and a TypeScript client directly from the application's OpenAPI document. Generated SDK files are disposable artifacts and should not be hand-edited.

## Design System Extractor

### `GET /api/v1/web/design-system`

Renders a public HTTP(S) page with Playwright/Chromium and analyzes the source response plus the runtime-rendered DOM/CSS. The endpoint is intended for modern React, Next.js, Vue, Nuxt, Angular, Svelte, Tailwind-like utility CSS, CSS Modules, CSS-in-JS, and runtime-generated styles.

Query parameter:

- `url`: required public HTTP(S) URL; userinfo and unsupported schemes are rejected.

The response includes `url`, `final_url`, `fetched_at`, extractor/schema versions, analysis metadata, normalized design-system tokens, and sanitized warnings. Token evidence includes confidence, source categories, and usage counts where meaningful.

The extractor analyzes bounded responsive viewports, computed styles, runtime CSS variables and styles, stylesheet rules, fonts, common components, layout geometry, icon signals, and framework hints. It never exposes raw HTML, JavaScript, or raw page CSS.

Security controls include initial SSRF validation, per-browser-request SSRF validation, redirect-hop validation, isolated non-persistent browser contexts, blocked downloads/media resources, guarded WebSocket routing where supported, GET/HEAD-only HTTP resource fetching, strict timeouts, resource budgets, and no generic form/action interaction. Public pages requiring authentication return `AUTHENTICATION_REQUIRED`.

The result may be partial. For example, cross-origin stylesheet access can be restricted by browser security, a third-party resource may be blocked by SSRF/resource policy, or a highly dynamic page may not stabilize within the bounded render period.

Configuration is server-side only and includes browser/navigation/render timeouts, redirect/request/response/aggregate-byte limits, DOM/CSS/component/resource limits, concurrent page capacity, responsive viewport definitions, and cache TTL. Cached results are keyed by normalized URL plus extractor/schema version and never contain browser authentication state.

Example response shape:

```json
{
  "url": "https://example.com/",
  "final_url": "https://example.com/",
  "fetched_at": "2026-09-05T12:00:00Z",
  "extractor_version": "1",
  "schema_version": "1",
  "analysis": {
    "duration_ms": 1834,
    "browser": "chromium",
    "viewport_count": 3,
    "resources_analyzed": 27,
    "bytes_downloaded": 123456,
    "partial": false
  },
  "design_system": {
    "colors": {},
    "typography": {},
    "spacing": {"values": [], "inferred_base_unit": null, "confidence": 0},
    "radii": {},
    "borders": {},
    "shadows": {},
    "breakpoints": {},
    "layout": {},
    "components": {},
    "custom_properties": {},
    "fonts": [],
    "icons": [],
    "framework_hints": []
  },
  "warnings": []
}
```

## Browser-Based Web Intelligence APIs

The following endpoints use the same isolated Playwright/Chromium and browser-level SSRF/resource policy as the Design System Extractor.

### `GET /api/v1/web/accessibility-audit`

Runs an automated audit against the hydrated/rendered page. It checks common image, ARIA, keyboard/focus, form-label, heading/landmark, language/title, link/button, and computed text-contrast conditions. Findings include severity, confidence, and WCAG mappings where reasonably determinable.

Example: `/api/v1/web/accessibility-audit?url=https://example.com`

This is an automated heuristic/static-render audit and is **not** an official WCAG certification or a replacement for manual accessibility testing.

### `GET /api/v1/web/core-web-vitals`

Measures browser-observed FCP, LCP, CLS and supported interaction timing, plus TTFB, navigation timing, resource transfer diagnostics, long tasks and a bounded bottleneck summary across configured mobile/desktop viewports.

Example: `/api/v1/web/core-web-vitals?url=https://example.com`

Values are synthetic browser measurements/estimates. They are not CrUX, real-user monitoring, PageSpeed Insights, or production-user INP data.

### `GET /api/v1/web/screenshot`

Renders a public HTTP(S) page in isolated Chromium and returns a bounded PNG, JPEG, or WebP image. Supports viewport/full-page captures, CSS element selectors, viewport dimensions, quality, and device scale factor.

Parameters: `url`, `selector`, `width`, `height`, `full_page`, `format`, `quality`, `device_scale_factor`.

The URL and all browser subresources remain subject to SSRF, redirect, request-count, byte, DOM, viewport, page-height, and screenshot-size controls. Forms are never submitted and arbitrary JavaScript supplied by the caller is never executed.

### `GET /api/v1/web/api-discovery`

Performs bounded passive public API discovery from browser-observed XHR/fetch traffic, document/script references, forms, and a small allowlisted set of conventional OpenAPI/Swagger documentation paths. It can identify JSON APIs, REST-like endpoints, GraphQL references, OpenAPI documents, and observed WebSocket URLs where browser instrumentation permits.

Example: `/api/v1/web/api-discovery?url=https://example.com`

This is not a penetration-testing, directory-bruteforcing, port-scanning, vulnerability-exploitation, authentication-bypass, or parameter-fuzzing tool. Response bodies are not returned as part of discovery results.

All four APIs can return partial results when individual resources are unavailable or configured budgets are reached. They never accept user credentials, cookies, authorization headers, or browser storage.
