"""ASGI middleware: request ID, structured request logging, security headers,
CORS, and configurable rate limiting.
"""

from __future__ import annotations

import re
import time
import uuid
from contextvars import ContextVar

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.config import Settings
from app.core.exceptions import ResourceLimitError
from app.core.logging import get_logger
from app.core.ratelimit import RateLimitDecision

logger = get_logger(__name__)

request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)


def get_request_id() -> str | None:
    return request_id_var.get()


def client_ip(request: Request) -> str:
    """Best-effort client address, preferring proxy-forwarded headers only when
    the app runs behind a trusted proxy (X-Forwarded-For is not trusted here
    by default to avoid spoofed rate-limit keys)."""
    if request.client:
        return request.client.host
    return "unknown"


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Attach a request_id and log each request completion."""

    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        super().__init__(app)
        self._settings = settings

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        supplied = request.headers.get("X-Request-ID", "").strip()
        request_id = (
            supplied
            if re.fullmatch(r"[A-Za-z0-9._-]{1,64}", supplied)
            else uuid.uuid4().hex
        )
        token = request_id_var.set(request_id)
        request.scope["request_id"] = request_id
        start = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:  # pragma: no cover - surfaced by handler
            duration_ms = (time.perf_counter() - start) * 1000
            logger.error(
                "unhandled_error",
                extra={
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": 500,
                    "duration_ms": round(duration_ms, 2),
                },
            )
            raise
        finally:
            request_id_var.reset(token)

        declared_length = response.headers.get("content-length")
        if declared_length:
            try:
                too_large = int(declared_length) > self._settings.max_response_body_bytes
            except ValueError:
                too_large = False
            if too_large:
                response = JSONResponse(
                    status_code=500,
                    content={
                        "error": {
                            "code": "RESPONSE_LIMIT",
                            "message": "The generated response exceeds the configured size limit.",
                            "request_id": request_id,
                        }
                    },
                )
        duration_ms = (time.perf_counter() - start) * 1000
        metrics = getattr(request.app.state, "metrics", None)
        route = request.scope.get("route")
        route_path = getattr(route, "path", None) or request.url.path
        if route is None and route_path.startswith("/api/"):
            route_path = "<unmatched>"
        if metrics is not None:
            metrics.inc_request(response.status_code, route_path, request.method)
            metrics.observe_duration(route_path, request.method, duration_ms)
        # Do not log sensitive query strings; log only the path.
        logger.info(
            "request_completed",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": round(duration_ms, 2),
            },
        )
        response.headers["X-Request-ID"] = request_id
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Apply sensible security headers to all responses."""

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Central per-client, per-policy rate limiting for API routes."""

    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        super().__init__(app)
        self._settings = settings

    @staticmethod
    def _policy(path: str, settings: Settings) -> tuple[str, int]:
        security = ("/jwt/", "/regex", "/password/", "/sql/")
        network = (
            "/http/", "/webpage/", "/robots/", "/sitemap/", "/opengraph/",
            "/tech-detect", "/redirect/", "/tls/", "/ports/", "/canonical/", "/web/design-system",
            "/content-type/", "/url/lookup", "/timezone/lookup",
        )
        expensive = (
            "/dns/", "/domain/", "/whois/", "/mx/", "/ip/lookup",
            "/email/analyze-domain",
        )
        if any(part in path for part in security):
            return "security", settings.rate_limit_security_requests
        if any(part in path for part in network):
            return "network", settings.rate_limit_network_requests
        if any(part in path for part in expensive):
            return "expensive", settings.rate_limit_expensive_requests
        return "general", settings.rate_limit_requests

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if not self._settings.rate_limit_enabled or not request.url.path.startswith("/api/"):
            return await call_next(request)
        limiter = getattr(request.app.state, "rate_limiter", None)
        if limiter is None:
            return await call_next(request)

        policy_name, limit = self._policy(request.url.path, self._settings)
        decision: RateLimitDecision = await limiter.check(
            f"rl:{policy_name}:{client_ip(request)}",
            limit,
            self._settings.rate_limit_window_seconds,
        )
        if not decision.allowed:
            metrics = getattr(request.app.state, "metrics", None)
            if metrics is not None:
                metrics.inc_rate_limited()
                if policy_name == "security":
                    metrics.inc_security_rejection("rate_limit")
            request_id = get_request_id() or uuid.uuid4().hex
            logger.info(
                "rate_limited",
                extra={"request_id": request_id, "policy": policy_name},
            )
            return JSONResponse(
                status_code=429,
                content={
                    "error": {
                        "code": "RATE_LIMITED",
                        "message": "Too many requests. Please try again later.",
                        "request_id": request_id,
                    }
                },
                headers={
                    "Retry-After": str(decision.reset_after),
                    "X-RateLimit-Limit": str(decision.limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(decision.reset_after),
                    "X-Request-ID": request_id,
                },
            )

        response = await call_next(request)
        response.headers.setdefault("X-RateLimit-Limit", str(decision.limit))
        response.headers.setdefault("X-RateLimit-Remaining", str(decision.remaining))
        response.headers.setdefault("X-RateLimit-Reset", str(decision.reset_after))
        return response


class RequestLimitMiddleware:
    """Streaming ASGI request-size guard."""

    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        self.app = app
        self._settings = settings

    @staticmethod
    def _header(scope: Scope, name: bytes) -> bytes | None:
        for key, value in scope.get("headers", []):
            if key.lower() == name:
                return value
        return None

    def _request_id(self, scope: Scope) -> str:
        raw = self._header(scope, b"x-request-id")
        if raw:
            try:
                value = raw.decode("ascii")
            except UnicodeDecodeError:
                value = ""
            if re.fullmatch(r"[A-Za-z0-9._-]{1,64}", value):
                return value
        return uuid.uuid4().hex

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = self._request_id(scope)
        raw_target = scope.get("raw_path", b"") + (
            b"?" + scope.get("query_string", b"")
            if scope.get("query_string")
            else b""
        )
        if len(raw_target) > self._settings.max_url_length:
            await self._reject(send, "Request URL exceeds the allowed length.", request_id)
            return

        if scope.get("method", "GET").upper() not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return

        content_type = (self._header(scope, b"content-type") or b"").lower()
        limit = self._settings.max_request_body_bytes
        if b"application/json" in content_type:
            limit = min(limit, self._settings.max_json_body_bytes)

        raw_length = self._header(scope, b"content-length")
        if raw_length:
            try:
                if int(raw_length) > limit:
                    await self._reject(send, "Request body exceeds the allowed size.", request_id)
                    return
            except ValueError:
                await self._reject(send, "Invalid Content-Length header.", request_id)
                return

        total = 0
        json_depth = 0
        json_nodes = 0
        in_string = False
        escaped = False

        async def limited_receive() -> dict[str, Any]:
            nonlocal total, json_depth, json_nodes, in_string, escaped
            message = await receive()
            if message.get("type") == "http.request":
                body = message.get("body", b"")
                total += len(body)
                if total > limit:
                    raise _RequestTooLarge
                if b"application/json" in content_type:
                    for byte in body:
                        if in_string:
                            if escaped:
                                escaped = False
                            elif byte == 92:  # backslash
                                escaped = True
                            elif byte == 34:  # quote
                                in_string = False
                            continue
                        if byte == 34:
                            in_string = True
                        elif byte in (123, 91):  # { [
                            json_depth += 1
                            json_nodes += 1
                        elif byte in (125, 93):  # } ]
                            json_depth = max(0, json_depth - 1)
                        if (
                            json_depth > self._settings.max_json_depth
                            or json_nodes > self._settings.max_json_nodes
                        ):
                            raise _RequestTooDeep
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _RequestTooLarge:
            await self._reject(send, "Request body exceeds the allowed size.", request_id)
        except _RequestTooDeep:
            await self._reject(send, "JSON structure exceeds the configured depth/node limit.", request_id)

    async def _reject(self, send: Send, message: str, request_id: str) -> None:
        import json

        body = json.dumps(
            {
                "error": {
                    "code": "RESOURCE_LIMIT",
                    "message": message,
                    "request_id": request_id,
                }
            },
            separators=(",", ":"),
        ).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                    (b"cache-control", b"no-store"),
                    (b"x-request-id", request_id.encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


class _RequestTooLarge(Exception):
    """Internal control-flow signal for the streaming request guard."""


class _RequestTooDeep(Exception):
    """Internal control-flow signal for the JSON structural guard."""

