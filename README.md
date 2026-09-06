# Awesome_API

> One self-hostable REST API for developer, security and networking utilities —
> email validation, DNS / WHOIS intelligence, HTTP & TLS inspection, password
> generation, encoding, codecs, cron, JWT and much more. SSRF-hardened,
> rate-limited, cached, observable, and fully offline-testable.

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB)
![FastAPI](https://img.shields.io/badge/Framework-FastAPI-009688.svg)
![Docker](https://img.shields.io/badge/Docker-ready-2496ED)
![Tests](https://img.shields.io/badge/Tests-280%20passing-2ea44f)
![License](https://img.shields.io/badge/License-MIT-blue.svg)

[![CI](https://github.com/Amirreza-Jabbari/Awesome_API/actions/workflows/ci.yml/badge.svg)](https://github.com/Amirreza-Jabbari/Awesome_API/actions/workflows/ci.yml)

**69 utility endpoints** behind a single versioned boundary (`/api/v1`),
organized into 11 categories. Built on a swappable provider architecture so
real backends (DNS, WHOIS/RDAP, GeoIP) can be replaced without touching the
route surface. Includes Playwright/Chromium for browser-rendered web analysis.

---

## Highlights

- **Runs with zero external API keys** — DNS via dnspython, WHOIS/RDAP from
  public registries, GeoIP selectable (`none` / `free` / `ip-api` / `maxmind`).
- **SSRF-hardened outbound fetching** — canonical host validation, DNS-rebinding
  (TOCTOU) defense, redirect revalidation, and pinned TCP connections.
- **Bounded by design** — request/body/JSON-depth/node limits, per-endpoint
  resource budgets, upstream response caps.
- **Rate limiting & caching** — per-IP policies (general/expensive/network/secure)
  and an async cache with TTL, coalescing and metrics. In-memory for single
  instances, Redis for distributed deployments.
- **Never fabricates data** — unknown fields are `null`; passwords are never
  cached, logged or persisted.
- **Uniform error contract** — `error.code` / `error.message` / `error.request_id`
  envelope, no internal traces leaked.
- **Offline, deterministic test suite** — providers are faked; CI runs clean.
- **Browser intelligence** — accessibility audit, Core Web Vitals estimation,
  design-system extraction, screenshots and API discovery rendered in isolated
  Chromium (installed in the Docker image, never during a request).

## Quick Start

### Docker (fastest)

```bash
git clone https://github.com/Amirreza-Jabbari/Awesome_API.git && cd Awesome_API

# Single instance, in-memory cache/rate limiter (no Redis required)
docker build -t awesome-api:latest .
docker run --rm -p 8000:8000 awesome-api:latest

# Or API + Redis for shared state across multiple instances
docker compose up -d --build
```

Open the interactive docs: <http://localhost:8000/docs>

### Install from source

```bash
git clone https://github.com/Amirreza-Jabbari/Awesome_API.git && cd Awesome_API
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cp .env.example .env             # optional — defaults work without it

uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
# or: make dev
```

> **Requirements:** Python 3.11+ (the Docker image uses 3.12). Redis is
> optional and only needed for shared caching / multi-instance rate limiting.

## Examples

### Generate a strong password

```bash
curl -X POST http://localhost:8000/api/v1/password/generate \
  -H "Content-Type: application/json" \
  -d '{"length":20}'
```

```json
{"random_password":"ZSRW8O5&G#Iw%nfOUiur"}
```

### Parse a URL

```bash
curl -X POST http://localhost:8000/api/v1/url/parse \
  -H "Content-Type: application/json" \
  -d '{"url":"https://user:pass@example.com:8443/a/b?q=1#frag"}'
```

```json
{
  "valid": true,
  "error": null,
  "scheme": "https",
  "host": "example.com",
  "hostname": "example.com",
  "port": 8443,
  "path": "/a/b",
  "raw_query": "q=1",
  "query": [{"name": "q", "value": "1"}],
  "params": {"q": "1"},
  "fragment": "frag",
  "username": "user",
  "password": "pass",
  "url_without_query": "https://user:pass@example.com:8443/a/b"
}
```

### Check a disposable email

```bash
curl -X POST http://localhost:8000/api/v1/email/disposable-check \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com"}'
```

```json
{"email":"test@example.com","domain":"example.com","is_disposable":false}
```

### Errors are uniform

```bash
curl -X POST http://localhost:8000/api/v1/email/disposable-check \
  -H "Content-Type: application/json" \
  -d '{"email":"not-an-email"}'
```

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "The supplied input is invalid.",
    "request_id": "7610471006c542d68c1a75d757992ecd"
  }
}
```

## API Reference

All utility endpoints live under `/api/v1`. They are **`POST`** (JSON body)
except the five browser intelligence tools under `/api/v1/web/*`, which are
**`GET`** with a `url` query parameter.

System endpoints: `GET /health`, `GET /ready`, `GET /version`, and
`GET /metrics` (when `METRICS_ENABLED=true`).

Interactive docs on the running app: `/docs` (Swagger UI), `/redoc` (ReDoc) and
the raw document at `/openapi.json`. Full schemas and error codes are in
[docs/api.md](docs/api.md).

### Email `4`

| Method | Endpoint | Utility |
| --- | --- | --- |
| POST | `/api/v1/email/disposable-check` | Check if an email domain is disposable |
| POST | `/api/v1/email/validate` | Validate an email address |
| POST | `/api/v1/email/analyze-headers` | Analyze raw email headers |
| POST | `/api/v1/email/analyze-domain` | Analyze an email domain's mail infrastructure |

### Domain & DNS `5`

| Method | Endpoint | Utility |
| --- | --- | --- |
| POST | `/api/v1/dns/lookup` | Look up DNS records for a domain |
| POST | `/api/v1/domain/lookup` | Aggregate domain intelligence |
| POST | `/api/v1/mx/lookup` | Look up MX records for a domain |
| POST | `/api/v1/whois/lookup` | Look up WHOIS/RDAP registration data |
| POST | `/api/v1/dnssec/validate` | Validate DNSSEC status of a domain |

### IP & Network `3`

| Method | Endpoint | Utility |
| --- | --- | --- |
| POST | `/api/v1/ip/lookup` | IP address intelligence |
| POST | `/api/v1/url/lookup` | URL / hostname intelligence |
| POST | `/api/v1/ports/check` | Check TCP port status |

### Web Analysis `13`

| Method | Endpoint | Utility |
| --- | --- | --- |
| POST | `/api/v1/user-agent/parse` | Parse a User-Agent header |
| POST | `/api/v1/webpage/lookup` | Extract webpage metadata |
| GET | `/api/v1/web/design-system` | Extract a rendered website design system |
| GET | `/api/v1/web/accessibility-audit` | Audit rendered accessibility |
| GET | `/api/v1/web/core-web-vitals` | Estimate Core Web Vitals in Chromium |
| GET | `/api/v1/web/screenshot` | Capture a rendered website screenshot |
| GET | `/api/v1/web/api-discovery` | Discover public API endpoints observed by Chromium |
| POST | `/api/v1/robots/analyze` | Analyze a `robots.txt` file |
| POST | `/api/v1/sitemap/analyze` | Analyze an XML sitemap |
| POST | `/api/v1/opengraph/analyze` | Extract Open Graph metadata |
| POST | `/api/v1/tech-detect` | Detect website technologies |
| POST | `/api/v1/redirect/analyze` | Trace URL redirect chains |
| POST | `/api/v1/canonical/check` | Check a page's canonical URL |

### Web Security `5`

| Method | Endpoint | Utility |
| --- | --- | --- |
| POST | `/api/v1/jwt/inspect` | Inspect a JWT token |
| POST | `/api/v1/jwt/generate` | Generate a signed JWT |
| POST | `/api/v1/http-headers/analyze` | Analyze HTTP response headers |
| POST | `/api/v1/security-headers/check` | Check security headers on a live URL |
| POST | `/api/v1/tls/lookup` | Look up a TLS certificate |

### Web & HTTP `5`

| Method | Endpoint | Utility |
| --- | --- | --- |
| POST | `/api/v1/http/request` | Build or execute an HTTP request |
| POST | `/api/v1/http/inspect` | Inspect an HTTP request |
| POST | `/api/v1/http/curl` | Generate a `curl` command |
| POST | `/api/v1/http/headers` | Generate raw HTTP header lines |
| POST | `/api/v1/url/parse` | Parse and dissect a URL |

### Data & Encoding `15`

| Method | Endpoint | Utility |
| --- | --- | --- |
| POST | `/api/v1/hash/generate` | Generate a hash digest |
| POST | `/api/v1/hash/identify` | Identify a hash algorithm |
| POST | `/api/v1/base64` | Encode or decode Base64 |
| POST | `/api/v1/url/codec` | Percent-encode or decode a URL component |
| POST | `/api/v1/html/entities` | Encode or decode HTML entities |
| POST | `/api/v1/uuid/generate` | Generate a UUID |
| POST | `/api/v1/uuid/validate` | Validate a UUID |
| POST | `/api/v1/ulid/generate` | Generate ULID(s) |
| POST | `/api/v1/ulid/validate` | Validate a ULID |
| POST | `/api/v1/json` | Format or validate JSON |
| POST | `/api/v1/json/diff` | Diff two JSON documents |
| POST | `/api/v1/json/patch` | Generate an RFC 6902 JSON Patch |
| POST | `/api/v1/yaml/convert` | Convert between YAML and JSON |
| POST | `/api/v1/xml/convert` | Convert between XML and JSON |
| POST | `/api/v1/unicode/inspect` | Inspect Unicode characters |

### Developer Tools `8`

| Method | Endpoint | Utility |
| --- | --- | --- |
| POST | `/api/v1/sql/format` | Format SQL statements |
| POST | `/api/v1/sql/minify` | Minify SQL statements |
| POST | `/api/v1/sql/validate` | Validate SQL structure |
| POST | `/api/v1/semver/analyze` | Analyze a semantic version |
| POST | `/api/v1/changelog/generate` | Generate a Keep-a-Changelog document |
| POST | `/api/v1/color/convert` | Convert between color formats |
| POST | `/api/v1/mock/generate` | Generate mock JSON data |
| POST | `/api/v1/mock/openapi` | Generate mock data from an OpenAPI document |

### Validation & Text `4`

| Method | Endpoint | Utility |
| --- | --- | --- |
| POST | `/api/v1/password/generate` | Generate a strong random password |
| POST | `/api/v1/password/strength` | Analyze password strength |
| POST | `/api/v1/phone/validate` | Validate a phone number |
| POST | `/api/v1/regex` | Test a regular expression |

### Files & Metadata `3`

| Method | Endpoint | Utility |
| --- | --- | --- |
| POST | `/api/v1/file/metadata` | Extract file type metadata from Base64 data |
| POST | `/api/v1/content-type/detect` | Detect a web resource's content type |
| POST | `/api/v1/image/metadata` | Extract image metadata from Base64 data |

### Time & Date `4`

| Method | Endpoint | Utility |
| --- | --- | --- |
| POST | `/api/v1/timestamp/convert` | Convert a timestamp or datetime string |
| POST | `/api/v1/timezone/lookup` | Look up a timezone by IP or coordinates |
| POST | `/api/v1/cron/generate` | Generate a cron expression from plain English |
| POST | `/api/v1/cron/parse` | Validate and expand a cron expression |

## Browser Intelligence

The five `GET /api/v1/web/*` endpoints render a public HTTP(S) page in an
isolated Chromium instance (via Playwright) inside the container:

- **Design System Extractor** — infers a normalized design system (CSS custom
  properties, typography, spacing, radii, shadows, breakpoints, components,
  fonts, icons, framework hints) with deterministic confidence scores and
  source attribution.
- **Accessibility Audit** — heuristic analysis of rendered accessibility and
  selected WCAG criteria. *Not* a certification tool.
- **Core Web Vitals** — synthetic FCP/LCP/CLS (+ supported INP) measurements.
  *Not* CrUX / real-user data.
- **Screenshot** — bounded PNG/JPEG/WebP capture of a page, viewport or element.
- **API Discovery** — passively observes browser network traffic and well-known
  endpoints to surface publicly observable API docs and JSON endpoints.

All browser tools follow the SSRF policy and resource budgets (requests,
response size, DOM/CSS nodes, images, fonts, timeouts, concurrency, redirects).
They are **public-page tools only** — no credentials, cookies, form submission,
brute forcing, port scanning or exploitation. Chromium is baked into the Docker
image; browser binaries are never downloaded during an API request.

## Configuration

Everything is environment-driven — copy `.env.example` to `.env` and adjust.
Redis is optional: without it the app falls back to bounded in-process
cache/rate limiting.

| Variable | Default | Purpose |
| --- | --- | --- |
| `APP_ENV` | `development` | Environment (`production` / `test` / `development`) |
| `DEBUG` | `false` | Error verbosity |
| `LOG_FORMAT` | `json` | `json` or `text` log output |
| `CORS_ORIGINS` | *(empty)* | Comma-separated allowed origins |
| `DNS_NAMESERVERS` | `1.1.1.1,1.0.0.1` | Comma-separated resolvers (empty = system) |
| `CACHE_ENABLED` | `true` | Enable caching |
| `REDIS_URL` | — | e.g. `redis://redis:6379/0` |
| `RATE_LIMIT_ENABLED` | `true` | Per-IP rate limiting |
| `GEOIP_PROVIDER` | `free` | `none`, `free`, `ip-api`, or `maxmind` |
| `METRICS_ENABLED` | `false` | Expose Prometheus `/metrics` |
| `WEB_*`, `HTTP_*`, `MAX_*` | — | Per-utility and global resource limits |

Rate-limited responses return `429` with `Retry-After` and `X-RateLimit-*`
headers. The full environment table and hardening checklist are in
[docs/deployment.md](docs/deployment.md).

## Security & Hardening

- **SSRF defense** — HTTP(S)-only, canonical hostname validation, resolution
  against the configured DNS, rejection of private/loopback/link-local/CGNAT/
  metadata/multicast/reserved targets, redirect revalidation, and DNS-pinned TCP
  connections that close the DNS-rebinding (TOCTOU) window.
- **Parser hardening** — `defusedxml` for XML, `yaml.safe_load`, bounded JSON
  walkers, Pillow byte/pixel budgets, timeout-capable `regex` engine.
- **Input limits** — centralized URL/body caps plus JSON structural depth/node
  guards; streaming upstream readers keep response memory bounded.
- **Secrets** — passwords generated with `secrets` (no modulo bias) are never
  cached or logged; no secrets in code, all config via environment.
- **Error hygiene** — no internal traces, parser details or provider internals
  are returned to clients.
- **Deployment** — non-root container user, health checks, TLS termination at a
  reverse proxy, multi-worker via uvicorn with proxy headers.

See [docs/security.md](docs/security.md) for the full model.

## Testing

The suite is fully offline and deterministic (all providers are faked):

```bash
pytest                       # or: make test
pytest --cov=app --cov-report=term-missing   # coverage report
pytest -q tests/test_fuzz.py # lightweight property/fuzz tests
```

See [docs/development.md](docs/development.md).

## Development

```bash
make dev          # run uvicorn with auto-reload on :8000
make lint         # ruff check .
make typecheck    # mypy .
make check        # lint + typecheck + test
make format       # ruff format + autofix
make generate-sdk # regenerate the Python & TypeScript SDKs from the live OpenAPI
```

Architecture and the documented way to add an endpoint:
[docs/architecture.md](docs/architecture.md) ·
[docs/development.md](docs/development.md)

## Documentation

| Document | Contents |
| --- | --- |
| [docs/api.md](docs/api.md) | Endpoint reference, schemas and error codes |
| [docs/architecture.md](docs/architecture.md) | Project layout and provider design |
| [docs/security.md](docs/security.md) | SSRF model, parser policy, limits |
| [docs/deployment.md](docs/deployment.md) | Environment table and hardening checklist |
| [docs/development.md](docs/development.md) | Local setup and how to add an endpoint |

## License

[MIT](LICENSE) © [Amirreza Jabbari](https://github.com/Amirreza-Jabbari)
