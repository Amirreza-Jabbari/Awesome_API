# Development

## Prerequisites

- Python 3.11+ (the production Docker image uses 3.11)
- Optional: Redis 7 (only for shared caching / multi-instance rate limiting;
  not required for local dev)

## Setup

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Copy the environment template and adjust as needed:

```bash
cp .env.example .env
```

## Running locally

```bash
uvicorn app.main:app --reload --loop app.core.eventloop:proactor_event_loop --host 0.0.0.0 --port 8000
# or: make dev
```

> **Windows note:** with `--reload` (or `--workers`) uvicorn switches to
> `asyncio.SelectorEventLoop`, which cannot spawn subprocesses — Playwright's
> node driver then fails during design-system browser startup with
> `NotImplementedError`. Passing `--loop app.core.eventloop:proactor_event_loop`
> (`app/core/eventloop.py`) forces the Proactor loop on Windows so the browser
> starts in every mode. It is a no-op on other platforms.

Interactive docs: http://localhost:8000/docs

Without Redis the app automatically falls back to an in-process cache and
rate limiter. Set `CACHE_ENABLED=false` / `RATE_LIMIT_ENABLED=false` to disable
them entirely.

## Linting & formatting

```bash
ruff check .                 # lint
ruff format .                # auto-format
make lint / make format
```

## Static typing

```bash
mypy .                       # strict mode over app/
make typecheck
```

## Tests

The test suite is **fully offline**: external providers (DNS, WHOIS/RDAP, GeoIP,
IP intelligence) are replaced with fakes in `tests/fakes.py`, so CI is
deterministic and never depends on the internet, public DNS, WHOIS servers or
third-party APIs.

```bash
pytest                       # full suite
pytest -q                    # quiet
pytest --cov=app --cov-report=term-missing   # coverage
make test / make test-cov
```

Tests are organised by service (`tests/test_*.py`) plus an end-to-end HTTP layer
(`tests/test_api.py`) that boots a fake-backed FastAPI app via TestClient and
verifies status codes, the JSON error envelope and validation behaviour. Security
tests live in `tests/test_ssrf.py`.

To run one file:

```bash
pytest tests/test_dns.py -v
```

## Project layout

```
app/
  api/v1/       route modules (one per utility)
  core/         config, logging, exceptions, middleware, metrics, ratelimit, security, dependencies
  providers/    swappable external backends (dns, whois, geoip, ipintel, hosting, email, web/ssrf)
  repositories/ cache + hosted-list repositories (fsm, redis)
  schemas/      pydantic request/response models
  services/     orchestration + error mapping
  utils/        pure helpers (domain, email, url, ip)
data/           disposable_hosts.txt, free_email_hosts.txt, risky_tlds.txt, malicious_hosts.txt
docs/           architecture.md, api.md, development.md, deployment.md
tests/          fakes + per-service unit tests + API tests
```

## Adding a new endpoint

1. Add a provider/protocol under `app/providers/` if a new external capability
   is needed.
2. Add a service under `app/services/` that owns the logic and error mapping.
3. Add request/response schemas under `app/schemas/`.
4. Add a thin route module under `app/api/v1/` and register it in
   `app/api/v1/router.py`.
5. Wire the service in `app/main.build_providers()` and add a dependency getter
   in `app/core/dependencies.py`.
6. Write offline tests (unit + API) with a fake provider.

Keep error handling consistent: raise exceptions from `app/core/exceptions.py`
so they map to the documented envelope automatically.

## OpenAPI and SDK workflow

The application OpenAPI document is generated from the FastAPI route and Pydantic definitions, then enriched centrally with representative examples and standard error responses. Validate the contract with:

```bash
make openapi-validate
```

Generate client artifacts with:

```bash
make generate-sdk
```

The generated Python and TypeScript clients are derived from the same OpenAPI source and should never be hand-edited.
