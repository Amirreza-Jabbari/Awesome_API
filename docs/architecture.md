# Architecture

Awesome_API is a production-ready, self-hostable FastAPI platform exposing a
fleet of developer, security and networking utilities behind one unified,
versioned API. This document describes the high-level design, the layering, the
provider/swappable patterns, caching, observability and the security model.

## Design goals

- **Offline-first locally, provider-pluggable externally.** Local utilities
  (password generation, phone/user-agent parsing) never leave the process.
  Network lookups (DNS, MX, RDAP/WHOIS, GeoIP) go through thin provider
  interfaces so real backends can be swapped without touching routes or
  services.
- **Never fabricate data.** Every response field is sourced from an actual
  provider, a local computation, or is `null`. The API does not invent values.
- **Safe by default.** Outbound fetchers are SSRF-hardened; private/loopback/
  metadata addresses are never sent to external providers.
- **Versioned and consistent.** All utilities live under `/api/v1/...` and
  share one error envelope.

## Layering

```
HTTP  (FastAPI + ASGI middleware)
  │
  ▼
Routes  (app/api/v1/*)          thin, map HTTP → service
  │
  ▼
Services (app/services/*)       orchestration, caching, error mapping
  │
  ▼
Providers (app/providers/*)     swappable external backends (DNS/WHOIS/GeoIP...)
  |
  ▼
Repositories (app/repositories) in-memory host lists, cache
```

Cross-cutting modules live in `app/core` (config, logging, exceptions,
metrics, ratelimit, middleware, security) and `app/utils` (pure helpers for
domain/email/URL/IP normalization).

### Routes

Routes depend on service interfaces injected through
`app.core.dependencies.get_*_service`, which pull pre-constructed instances from
`request.app.state`. `app.main.build_providers()` wires everything once at
startup and exposes it on `app.state`, keeping routing thin and testable.

## Provider architecture

External capabilities are abstracted as `Protocol`s in `app/providers/*/base.py`:

| Capability   | Base protocol / models        | Implementations                          |
| ------------ | ----------------------------- | ---------------------------------------- |
| DNS          | `DNSProvider`, `DNSQuery`     | `DNSPythonProvider` (dnspython)          |
| WHOIS/RDAP   | `WhoIsProvider`               | `RDAPProvider`, `PythonWhoisProvider`    |
| GeoIP        | `GeoIPProvider`, `GeoIPResult`| `FreeIPIntelligenceProvider`, `NullGeoIPProvider`, `IpApiGeoIPProvider`, `MaxMindGeoIPProvider` |
| IP intel     | `IPIntelligenceProvider`      | `NullIPIntelligenceProvider`             |

WHOIS/RDAP lookups prefer RDAP (structured, RFC-standardised) and fall back to
legacy WHOIS. Providers raise domain exceptions (`app.core.exceptions`) so the
service layer can degrade gracefully and map failures to clean HTTP statuses.

### Local processing (images)

`app/services/image_service.py` is a purely local pipeline with no external
provider: it decodes, re-encodes, resizes, renders PDFs and (optionally) runs
AI background removal entirely in memory. CPU/IO work runs in worker threads
(`asyncio.to_thread`) behind a hard timeout and a concurrency semaphore, all
upload and output sizes are bounded by centralized settings, and metadata
(EXIF/GPS) is stripped during re-encoding. No file is written to disk between
requests.

### GeoIP / IP-intelligence

GeoIP and IP-intelligence providers return `None` for any field they cannot
establish; the null providers return `None` for every uncertain signal so the
API never emits invented threat intelligence.

## Caching

`app/repositories/cache.py` exposes a `Cache` protocol with three
implementations:

- `MemoryCache` — in-process TTL cache, ideal for dev/single-instance.
- `RedisCache` — shared cache for multi-instance deployments (values stored as
  JSON with `EX` TTL).
- `NullCache` — no-op when caching is disabled.

Caching is used for slow, provider-backed lookups (DNS, MX, RDAP/WHOIS, IP
intelligence). **Password generation is never cached, logged or persisted.**

If Redis is unreachable at startup the app logs a warning and falls back to
in-memory. Cache and rate limiting both become no-ops when disabled, so the API
runs without Redis.

## Rate limiting

`app/core/ratelimit.py` provides:

- `MemoryRateLimiter` — bounded per-IP fixed-window limiter (single instance).
- `RedisRateLimiter` — atomic fixed-window counter shared across instances.
- `NullRateLimiter` — disabled.

A fixed-window policy is applied via
`RateLimitMiddleware` and returns `429` with a `RATE_LIMITED` error envelope,
configurable via `RATE_LIMIT_REQUESTS` and
`RATE_LIMIT_WINDOW_SECONDS`.

## Observability

- Structured JSON logs with request IDs (opt-in to per-request tracing) via
  `app/core/logging.py`.
- Prometheus metrics (`/metrics`, only when `METRICS_ENABLED=true`) from
  `app/core/metrics.py` — provider latencies, cache hit/miss, error counts.
- Readiness (`/ready`) reports DNS + cache availability; liveness (`/health`)
  is a simple TCP/app probe.

## Security model

See also `docs/deployment.md` and `docs/security.md`.

- **SSRF protection** (`app/providers/web/ssrf.py`): hostname is DNS-resolved
  before connect and rejected when any address is private/loopback/link-local/
  CGNAT/metadata/multicast/reserved. The webpage fetcher re-resolves the peer
  after fetch to blunt DNS rebinding, and streams the body with a configurable
  size cap.
- **Outbound discipline**: private/internal addresses are never sent to external
  GeoIP/intelligence providers.
- **Secrets generation**: password generator uses `secrets` and guarantees
  per-category minimums without modulo bias.
- **Headers**: `SecurityHeadersMiddleware` adds hardening headers.
- **Config**: settings via environment variables in `app/core/config.py`; no
  secrets in code.

## Configuration

All runtime settings live in `app/core/config.py` (pydantic-settings, `.env`
aware). See `.env.example` and `docs/deployment.md` for the full variable table.

## Testing

See `docs/development.md`. The test suite is fully offline: external providers
are faked (`tests/fakes.py`) so CI is deterministic and never depends on the
internet, public DNS, WHOIS servers or third-party APIs.

## Production-hardening boundaries

- `app/core/limits.py` contains reusable JSON/header resource guards.
- `app/core/health.py` owns readiness diagnostics so dependency checks remain
  safe and centralized.
- `app/core/openapi.py` enriches the generated contract without changing route
  handlers.
- `app/api/router.py` is the version boundary; V1 can coexist with a future V2.
- `scripts/generate_sdk.py` generates disposable clients directly from OpenAPI.
