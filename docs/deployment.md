# Deployment

## Environment variables

All configuration is environment-driven and centralised in
`app/core/config.py` (pydantic-settings). Copy `.env.example` to `.env` locally;
in production, inject real values via your orchestrator. **Never commit `.env`.**

| Variable                     | Default                | Description                                                     |
| ---------------------------- | ---------------------- | --------------------------------------------------------------- |
| `APP_NAME`                   | `Awesome_API`          | Application display name.                                       |
| `APP_ENV`                    | `development`          | `development`, `test` or `production`.                          |
| `APP_VERSION`                | `1.0.0`                | Version reported by `/version`.                                 |
| `DEBUG`                      | `false`                | Enable debugging. Keep `false` in production.                   |
| `HOST` / `PORT`              | `0.0.0.0` / `8000`     | Bind address for uvicorn (used by container).                   |
| `CORS_ORIGINS`               | *(empty)*              | Comma-separated allowed origins; empty disables CORS.           |
| `LOG_LEVEL`                  | `INFO`                 | Logging level.                                                  |
| `LOG_FORMAT`                 | `json`                 | `json` or `text`.                                               |
| `DNS_NAMESERVERS`            | `1.1.1.1,1.0.0.1`      | Comma-separated resolvers for the DNS provider.                 |
| `DNS_TIMEOUT`                | `3`                    | Per-query DNS timeout (seconds).                                |
| `DNS_LIFETIME`               | `5`                    | Overall DNS resolution lifetime (seconds).                      |
| `CACHE_ENABLED`              | `true`                 | Enable caching.                                                 |
| `REDIS_URL`                  | `redis://redis:6379/0` | Redis DSN (required only for shared/multi-instance caching).    |
| `DNS_CACHE_TTL`              | `300`                  | TTL (seconds) for DNS/MX lookups.                               |
| `WHOIS_CACHE_TTL`            | `3600`                 | TTL (seconds) for RDAP/WHOIS lookups.                           |
| `IP_LOOKUP_CACHE_TTL`        | `3600`                 | TTL (seconds) for IP intelligence.                              |
| `RATE_LIMIT_ENABLED`         | `true`                 | Enable per-IP rate limiting.                                    |
| `RATE_LIMIT_REQUESTS`        | `60`                   | Max requests per window.                                        |
| `RATE_LIMIT_WINDOW_SECONDS`  | `60`                   | Rate-limit window (seconds).                                    |
| `WEBPAGE_TIMEOUT`            | `10`                   | Total webpage fetch timeout (seconds).                          |
| `WEBPAGE_CONNECT_TIMEOUT`    | `5`                    | Connect timeout (seconds).                                      |
| `WEBPAGE_READ_TIMEOUT`       | `8`                    | Read timeout (seconds).                                         |
| `WEBPAGE_MAX_RESPONSE_SIZE`  | `5242880`              | Max HTML bytes streamed (5 MB default).                         |
| `WEBPAGE_MAX_REDIRECTS`      | `5`                    | Max redirects followed.                                         |
| `WEBPAGE_USER_AGENT`         | `Awesome_API/...`      | UA sent by the fetcher.                                         |
| `HTTP_TIMEOUT`               | `10`                   | Generic outbound HTTP timeout (seconds).                        |
| `GEOIP_PROVIDER`             | `free`                 | `free`, `none`, `ip-api`, or `maxmind`.                         |
| `GEOIP_API_KEY`              | *(empty)*              | MaxMind database path / API key (as applicable).                |
| `WHOIS_TIMEOUT` / `RDAP_TIMEOUT` | `10` / `10`        | Registry lookup timeouts (seconds).                             |
| `METRICS_ENABLED`            | `false`                | Expose `/metrics`.                                              |
| `METRICS_PORT`               | `9090`                 | (informational) metrics port.                                   |
| `IMAGE_WIDTH_MAX`            | `24000`                | Max resize/convert output width (pixels).                       |
| `IMAGE_CANVAS_MAX_DIMENSION` | `8192`                 | Max canvas width/height for `/image/resize`.                    |
| `IMAGE_TARGET_SIZE_MIN_KB`   | `8`                    | Minimum `target_size_kb` for image conversion.                  |
| `IMAGE_TARGET_SIZE_MAX_KB`   | `4000`                 | Maximum `target_size_kb` for image conversion.                  |
| `IMAGE_MAX_OUTPUT_BYTES`     | `15000000`             | Max single output file size (bytes).                            |
| `IMAGE_MAX_PDF_PAGES`        | `50`                   | Max PDF pages for pagination and rasterization.                 |
| `IMAGE_MAX_PDF_DPI`          | `300`                  | Cap for the rasterize DPI parameter.                            |
| `IMAGE_MAX_RASTERIZE_BYTES`  | `40000000`             | Total ZIP size cap when rasterizing PDF pages.                  |
| `IMAGE_MAX_CONCURRENT`       | `2`                    | Concurrent image operations per process.                        |
| `IMAGE_TIMEOUT_SECONDS`      | `60`                   | Per-operation processing timeout (seconds).                     |
| `IMAGE_BACKGROUND_REMOVAL_ENABLED` | `false`         | Enable AI background removal (needs the `[image-ai]` extra).    |
| `IMAGE_REMBG_MODEL`          | `u2net`                | rembg model used by `/image/background`.                        |

## Run without Redis

Redis is only needed for shared caching and multi-instance rate limiting. If it
is disabled or unreachable, the app logs a warning and uses an in-process cache
and rate limiter — or no-ops if `CACHE_ENABLED`/`RATE_LIMIT_ENABLED` are false.

## Run with Docker (single instance, no Redis)

```bash
docker build -t awesome-api:latest .
docker run --rm -p 8000:8000 \
  -e CACHE_ENABLED=false -e RATE_LIMIT_ENABLED=false \
  awesome-api:latest
```

## Run with Docker Compose (API + Redis)

```bash
docker compose up -d --build
```

Exposes the API on `localhost:8000` and Redis on `localhost:6379`. The API is
configured via environment variables in `docker-compose.yml`.

## Production hardening

- Set `APP_ENV=production`, `DEBUG=false`, `LOG_FORMAT=json`.
- Put the service behind TLS (e.g. a reverse proxy) and set `CORS_ORIGINS` to
  your actual origins.
- Terminate TLS at the proxy and forward proxy headers with
  `--proxy-headers --forwarded-allow-ips '<trusted-proxy-ips>'`.
- Configure `DNS_NAMESERVERS` to resolvers you trust.
- If serving the webpage-metadata endpoint, keep the SSRF guard enabled (it is
  on by default) and consider restricting outbound egress at the network layer.
- Use a non-root user (the Dockerfile already does) and drop Linux capabilities
  where your platform allows.
- Rotate/omit any provider keys; never log or commit them.

## Uvicorn workers

Run with a single worker unless you have a shared cache (Redis) for rate
limiting and caching, since in-memory state is per-process:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4 \
  --proxy-headers --forwarded-allow-ips "*"
```

## Health checks

- `/health` — liveness; returns `200` when the app is up.
- `/ready` — readiness; reports DNS + cache availability.

Wire the reverse proxy / orchestrator health checks to `/health` (liveness) and
`/ready` (readiness).

## Observability

Structured JSON logs carry a request ID per request. Prometheus metrics are
available at `/metrics` when `METRICS_ENABLED=true`; scrape on a separate
internal port and do not expose `/metrics` publicly if it is sensitive.