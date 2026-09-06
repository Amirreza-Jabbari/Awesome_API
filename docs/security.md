# Security Model

## SSRF

Outbound HTTP is limited to `http` and `https`. User-controlled hostnames are normalized and resolved before connection. Any non-global address is rejected, including loopback, private, link-local, multicast, reserved, unspecified, CGNAT and cloud metadata ranges.

The HTTP transport pins the hostname to the exact address returned by the SSRF check while preserving the original hostname for HTTP `Host` and TLS SNI semantics. Redirects are processed one hop at a time and revalidated before the next connection.

The service does not provide arbitrary proxying, credential injection into browser state, or support for `file://`, `ftp://` or other local-resource schemes.

## Parsers

- XML uses `defusedxml` and has an element budget.
- YAML uses `safe_load` and rejects recursive alias structures during conversion.
- JSON operations enforce body, depth and node budgets.
- Mock/OpenAPI generation has bounded nesting and node generation.
- Image metadata extraction enforces decoded-byte and pixel budgets before loading pixels.
- User regexes use the timeout-capable `regex` engine and a bounded input/match budget.

## JWT

JWT inspection is deliberately non-verifying: it decodes metadata without accepting a caller-supplied key. JWT generation allowlists HS256/HS384/HS512 and removes caller control over `alg`/`typ` headers. HMAC secrets must provide at least 256 bits of UTF-8 key material.

Generated JWT secrets and tokens are not logged or persisted by the API.

## SQL tools

SQL endpoints perform formatting, tokenization and structural checks only. They do not create database connections, invoke a shell, or execute submitted statements.

## Rate limiting

Rate limiting is centralized and policy-based. Redis provides cross-instance counters when configured; the local fallback is bounded to avoid attacker-controlled key growth. Health endpoints are outside the API rate-limit path.

## Sensitive data

Logs and metrics deliberately omit request bodies, credentials, authorization headers, cookies, arbitrary URLs and request IDs as metric labels. Error responses contain safe messages and a request correlation ID, not stack traces or provider internals.

## Reporting

If a vulnerability is found, provide a minimal reproduction, affected endpoint/component, expected security boundary and impact. Do not include real credentials or private data in a report.

## Browser-rendered Design System extraction

The Design System Extractor runs public pages inside an isolated, non-persistent Chromium context. Initial URLs are checked by `SSRFGuard` before browser navigation. Every HTTP(S) browser resource request is intercepted and independently resolved/validated before a single redirect hop is fetched; redirect requests therefore pass through the same policy rather than inheriting trust from the original URL.

The browser context has no persisted cookies or storage, blocks service workers and downloads, permits only GET/HEAD resource fetching, and rejects media/event-stream style resources that are not useful for design-system inference. Request count, response size, aggregate bytes, stylesheet/font/image count, DOM nodes, CSS rules, viewport count, concurrency, redirects and navigation/render time are bounded by centralized settings. The target page is never given server-side objects, credentials, environment variables or application secrets.

Extraction is observational. The service does not submit forms or click arbitrary controls. Hover interaction is not required for token inference; pseudo-class information is derived from accessible CSS rules when available. Authentication is unsupported and a target returning HTTP 401 is classified as `AUTHENTICATION_REQUIRED`.

The browser is launched with Chromium sandboxing enabled. The production Docker image installs Chromium and its OS dependencies at image-build time, and the application runs as a non-root user. If the browser cannot be started, the core API remains available and the Design System endpoint returns a controlled browser-unavailable error rather than silently falling back to static scraping.

## Browser Web Intelligence Security

Accessibility Audit, Core Web Vitals, Screenshot, API Discovery, and Design System extraction share the existing BrowserManager and browser request interception layer. Every initial target is checked by the centralized SSRF guard before navigation, and browser HTTP(S) resources are checked again before they are fetched. Redirect destinations therefore pass through the same policy rather than inheriting trust from the initial URL.

Browser contexts are isolated and ephemeral: cookies, localStorage/sessionStorage, service workers, and authentication state are not shared between unrelated requests. Downloads are disabled, non-GET/HEAD browser requests are blocked, media-heavy resource classes are restricted, and resource/request/DOM/viewport/screenshot budgets are bounded.

The browser receives no application secrets. Extracted HTML, CSS, JavaScript, response bodies, cookies, authorization headers, and screenshot contents are not logged. API Discovery reports metadata rather than response bodies. Automated analysis never submits forms or clicks arbitrary controls.
