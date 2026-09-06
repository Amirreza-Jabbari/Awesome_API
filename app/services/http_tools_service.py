"""Web & HTTP developer tools (request builder, inspector, curl, headers, URL).

Security is the top priority here. Every live fetch is routed through the same
SSRF guard and redirect re-validation policy as webpage analysis. We never
inject credentials into browser-stored state, never follow a redirect without
re-checking, cap response size and timeouts, and refuse ``file://``/``ftp://``
and other non-http(s) schemes. Building a request (``execute=false``) performs
no network I/O at all; it only constructs a canonical request and its curl
representation.
"""
from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse

import httpx

from app.core.config import Settings
from app.core.exceptions import (
    ProviderUnavailableError,
    ResolutionBlockedError,
    ResourceLimitError,
    SSRFBlockedError,
    ValidationError,
)
from app.providers.web.ssrf import SSRFGuard, pin_address, unpin_address
from app.schemas.http_tools import HTTPQueryParam

_REDIRECT_CODES = (301, 302, 303, 307, 308)
_DEFAULT_UA = "Awesome_API/1.0 (+https://example.com/bot)"


@dataclass(slots=True)
class FetchOutcome:
    error: str | None
    status_code: int | None
    reason: str | None
    headers: dict[str, str]
    body: bytes
    final_url: str
    redirects: list[dict[str, Any]]
    elapsed_ms: float


class HTTPToolsService:
    """Local, SSRF-hardened HTTP request building and inspection tools."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        guard: SSRFGuard,
        settings: Settings,
        metrics: Any | None = None,
    ) -> None:
        self._client = client
        self._guard = guard
        self._settings = settings
        self._metrics = metrics

    # -- request building ----------------------------------------------------

    def build_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None,
        query: list[HTTPQueryParam] | list[dict[str, str]],
        body: str | None,
        body_type: str,
        auth_type: str,
        auth_username: str | None,
        auth_password: str | None,
        auth_token: str | None,
        include_content_length: bool = False,
    ) -> dict[str, Any]:
        from app.utils.url import normalize_url
        try:
            normalized = normalize_url(url)
        except ValidationError:
            raise
        parsed = urlparse(normalized)

        final_headers = {k: str(v) for k, v in (headers or {}).items()}
        from app.core.limits import validate_header_map
        validate_header_map(
            final_headers,
            max_headers=self._settings.http_tools_max_headers,
            max_name_length=128,
            max_value_length=8192,
        )

        body_bytes, content_type_header, body_error = self._encode_body(body, body_type)
        if body_error:
            raise ValidationError(body_error)
        if body_bytes is not None and len(body_bytes) > self._settings.max_request_body_bytes:
            raise ResourceLimitError("HTTP request body exceeds the allowed size.")

        # Recompute query params into a canonical string.
        pairs = [
            (pq.name, pq.value)
            if isinstance(pq, HTTPQueryParam)
            else (str(pq.get("name", "")), str(pq.get("value", "")))
            for pq in query or []
        ]
        canonical_query = urlencode(pairs)

        # Authorization headers.
        if auth_type == "basic":
            credential = f"{auth_username or ''}:{auth_password or ''}"
            final_headers["Authorization"] = "Basic " + base64.b64encode(
                credential.encode("utf-8")
            ).decode("ascii")
        elif auth_type == "bearer":
            final_headers["Authorization"] = "Bearer " + (auth_token or "")

        validate_header_map(
            final_headers,
            max_headers=self._settings.http_tools_max_headers,
            max_name_length=128,
            max_value_length=8192,
        )

        # Curl command representation (never executes).
        curl = self._build_curl(
            method, parsed, canonical_query, final_headers, body, body_bytes, body_type,
            auth_type, auth_username, auth_password, auth_token,
        )

        host = parsed.hostname or ""
        port = self._default_port(parsed)

        return {
            "mode": "build",
            "method": method.upper(),
            "url": normalized if not canonical_query else normalized.split("?")[0],
            "final_url": None,
            "host": host,
            "port": port,
            "ip_addresses": [],
            "ssrf_checked": False,
            "headers": self._sorted_headers(final_headers),
            "raw_query": canonical_query,
            "body": body if body is not None else None,
            "body_length": len(body_bytes) if body_bytes is not None else 0,
            "content_type": content_type_header,
            "curl": curl,
            "status_code": None,
            "reason": None,
            "response_headers": {},
            "response_body": None,
            "response_truncated": False,
            "response_size": 0,
            "is_json": False,
            "elapsed_ms": None,
            "redirects": [],
            "error": None,
        }

    def _build_curl(
        self,
        method: str,
        parsed: Any,
        query: str,
        headers: dict[str, str],
        body: str | None,
        body_bytes: bytes | None,
        body_type: str,
        auth_type: str,
        auth_username: str | None,
        auth_password: str | None,
        auth_token: str | None,
    ) -> str:
        parts = ["curl"]
        parts.append(f"-X {method.upper()}")
        final = parsed.scheme + "://" + parsed.netloc + (parsed.path or "") + parsed.params
        sep = "&" if query else "?"
        if query:
            final += sep + query

        upper = method.upper()
        if upper in ("POST", "PUT", "PATCH", "DELETE"):
            if body_bytes is not None:
                parts.append("--data-raw '{}'".format(_shell_escape(body_bytes.decode("utf-8"))))
            else:
                parts.append("--data ''")

        for name, value in sorted(headers.items()):
            parts.append(f"-H '{name}: {_shell_escape(value)}'")

        if body_type == "json" and body is not None:
            parts.append("-H 'Content-Type: application/json'")
        elif body_type == "form" and body is not None:
            parts.append("-H 'Content-Type: application/x-www-form-urlencoded'")

        if auth_type == "basic":
            parts.append("-u '{}:{}'".format(_shell_escape(auth_username or ""),
                                         _shell_escape(auth_password or "")))
        elif auth_type == "bearer":
            pass

        parts.append(f"'{final}'")
        return " ".join(parts)

    @staticmethod
    def _default_port(parsed: Any) -> int:
        if parsed.port:
            return int(parsed.port)
        return 443 if parsed.scheme == "https" else 80

    @staticmethod
    def _sorted_headers(headers: dict[str, str]) -> dict[str, str]:
        return {k: v for k, v in sorted(headers.items())}

    @staticmethod
    def _encode_body(
        body: str | None, body_type: str
    ) -> tuple[bytes | None, str | None, str | None]:
        """Return (encoded body, content-type header, error message)."""
        if body is None:
            return None, None, None
        if body_type == "json":
            try:
                json.loads(body)
            except json.JSONDecodeError as exc:
                return None, None, f"Body is not valid JSON: {exc}"
            return body.encode("utf-8"), "application/json; charset=utf-8", None
        if body_type == "form":
            items = parse_qsl(body, keep_blank_values=True)
            encoded = urlencode(items)
            return encoded.encode("utf-8"), "application/x-www-form-urlencoded; charset=utf-8", None
        if body_type == "xml":
            return body.encode("utf-8"), "application/xml; charset=utf-8", None
        return body.encode("utf-8"), None, None

    # -- curl generator ------------------------------------------------------

    def generate_curl(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None,
        query: list[dict[str, str]] | None,
        body: str | None,
        body_type: str,
        auth_type: str,
        auth_username: str | None,
        auth_password: str | None,
        auth_token: str | None,
        pretty: bool,
        include_headers: bool,
        follow_redirects: bool,
        compressed: bool,
        silent: bool,
    ) -> dict[str, Any]:
        built = self.build_request(
            method, url, headers, query or [], body, body_type,
            auth_type, auth_username, auth_password, auth_token,
        )
        command = built.get("curl") or ""
        base_flags: list[str] = []
        if include_headers:
            base_flags.append("-i")
        if follow_redirects:
            base_flags.append("-L")
        if compressed:
            base_flags.append("--compressed")
        if silent:
            base_flags.append("-s")
        if base_flags and command.startswith("curl"):
            command = "curl " + " ".join(base_flags) + command[len("curl"):]
        if pretty:
            command = command.replace(" ", " \\\n  ")
        return {
            "command": command,
            "flags": {
                "method": built.get("method"),
                "url": built.get("url"),
                "headers": len(built.get("headers") or {}),
                "has_body": (built.get("body_length") or 0) > 0,
                "auth": auth_type,
                "include_headers": include_headers,
                "follow_redirects": follow_redirects,
                "compressed": compressed,
                "silent": silent,
                "pretty": pretty,
            },
        }

    # -- request execution ------------------------------------------------------

    async def execute(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None,
        query: list[HTTPQueryParam] | list[dict[str, str]],
        body: str | None,
        body_type: str,
        auth_type: str,
        auth_username: str | None,
        auth_password: str | None,
        auth_token: str | None,
        timeout: float,
    ) -> dict[str, Any]:
        from app.utils.url import normalize_url
        built = self.build_request(
            method, url, headers, query, body, body_type,
            auth_type, auth_username, auth_password, auth_token,
        )
        if (built.get("error")) is not None:
            return built
        target = built["url"]
        raw_query = built.get("raw_query") or ""
        if raw_query:
            target += ("&" if "?" in target else "?") + raw_query
        outcome = await self._fetch(
            normalize_url(target),
            str(built.get("method") or "GET"),
            built.get("headers"),
            built.get("body"),
            True,
            int(self._settings.http_tools_max_redirects),
            min(
                int(self._settings.http_tools_max_response_size),
                int(self._settings.max_upstream_response_bytes),
            ),
            timeout,
        )
        merged = dict(built)
        merged["mode"] = "execute"
        merged["final_url"] = None
        merged["ssrf_checked"] = True
        body_text = None
        if outcome.body and not outcome.error:
            ctype = outcome.headers.get("content-type", "")
            body_text = self._decode_body(outcome.body, ctype)
        is_json = False
        if body_text and "json" in (outcome.headers.get("content-type") or "").lower():
            try:
                json.loads(body_text)
                is_json = True
            except json.JSONDecodeError:
                is_json = False
        merged.update(
            {
                "url": target,
                "final_url": outcome.final_url,
                "status_code": outcome.status_code,
                "reason": outcome.reason,
                "response_headers": outcome.headers,
                "response_body": body_text,
                "response_truncated": False,
                "response_size": len(outcome.body),
                "is_json": is_json,
                "elapsed_ms": outcome.elapsed_ms,
                "redirects": [{"status_code": h["status"], "location": h["location"]}
                              for h in outcome.redirects],
                "error": outcome.error,
            }
        )
        return merged

    # -- headers generator ---------------------------------------------------

    def generate_headers(
        self,
        headers: list[dict[str, str]],
        style: str,
        include_content_length: bool,
    ) -> dict[str, Any]:
        lines: list[str] = []
        normalized: list[dict[str, str]] = []
        issues: list[dict[str, object]] = []
        names = set()

        def clean_name(name: str) -> str:
            if style == "lowercase":
                return name.lower()
            if style == "uppercase":
                return name.upper()
            return name

        for idx, header in enumerate(headers):
            name = (header.get("name") or "").strip()
            value = (header.get("value") or "").strip()
            display = clean_name(name)
            if not name:
                issues.append({"index": idx, "issue": "empty header name"})
                continue
            if name.lower() in names:
                issues.append({"index": idx, "issue": "duplicate header name"})
            names.add(name.lower())
            normalized.append({"name": display, "value": value})
            lines.append(f"{display}: {value}")

        if include_content_length:
            total = sum(len(value.encode("utf-8")) for header in normalized
                        for value in [header["value"]])
            name = "Content-Length" if style != "lowercase" else "content-length"
            lines.append(f"{name}: {total}")

        return {
            "raw": "\r\n".join(lines) + ("\r\n" if lines else ""),
            "count": len(normalized),
            "normalized": normalized,
            "issues": issues,
        }

    # -- URL parser ----------------------------------------------------------

    @staticmethod
    def parse_url(url: str) -> dict[str, Any]:
        try:
            parsed_urlparse = urlparse(url)
            if parsed_urlparse.scheme and parsed_urlparse.scheme.lower() not in ("http", "https"):
                return {"valid": False, "error": "unsupported scheme",
                        "scheme": parsed_urlparse.scheme}
            bool(parsed_urlparse.scheme)
            normalized = url.strip()
            if "://" not in normalized:
                normalized = "https://" + normalized
            parsed = urlparse(normalized)
            if not parsed.hostname:
                return {"valid": False, "error": "URL has no host"}
        except ValueError as exc:
            return {"valid": False, "error": str(exc)}

        host = parsed.hostname
        query_items = parse_qsl(parsed.query, keep_blank_values=True)
        params = {k: v for k, v in query_items}
        path = parsed.path or ""
        return {
            "valid": True,
            "error": None,
            "scheme": parsed.scheme,
            "host": host,
            "hostname": host,
            "port": parsed.port,
            "path": path,
            "raw_query": parsed.query,
            "query": [{"name": k, "value": v} for k, v in query_items],
            "params": params,
            "fragment": parsed.fragment,
            "username": parsed.username,
            "password": parsed.password,
            "url_without_query": f"{parsed.scheme}://{parsed.netloc}{path}",
        }

    # -- live inspection / execution ------------------------------------------

    async def inspect(
        self,
        url: str,
        method: str,
        headers: dict[str, str] | None,
        body: str | None,
        follow_redirects: bool,
        max_redirects: int,
        max_body_size: int,
        timeout: float,
    ) -> dict[str, Any]:
        from app.utils.url import normalize_url
        try:
            normalized = normalize_url(url)
        except ValidationError:
            raise
        parsed = urlparse(normalized)
        host = parsed.hostname or ""

        outcome = await self._fetch(
            normalized, method, headers, body, follow_redirects, max_redirects,
            min(max_body_size, self._settings.max_upstream_response_bytes), timeout,
        )

        if not outcome.error:
            truncated = False
            ctype = outcome.headers.get("content-type", "")
            body_text = None
            if outcome.body:
                body_text = self._decode_body(outcome.body, ctype)
            is_json = "json" in ctype.lower()
            json_type = None
            if is_json and body_text:
                try:
                    parsed_json = json.loads(body_text)
                    json_type = "array" if isinstance(parsed_json, list) \
                        else ("object" if isinstance(parsed_json, dict) else "scalar")
                except json.JSONDecodeError:
                    json_type = None
            return {
                "valid": True,
                "error": None,
                "url": normalized,
                "final_url": outcome.final_url,
                "status_code": outcome.status_code,
                "reason": outcome.reason,
                "headers": outcome.headers,
                "cookies": self._parse_cookies(outcome.headers),
                "body_preview": self._truncate(body_text),
                "body_size": len(outcome.body),
                "body_truncated": truncated,
                "is_json": is_json,
                "json_type": json_type,
                "content_type": ctype,
                "charset": self._charset(ctype),
                "elapsed_ms": outcome.elapsed_ms,
                "redirects": outcome.redirects,
                "host": host,
                "ip_addresses": [],
                "ssrf_checked": True,
            }
        return self._error_result(normalized, outcome.error)

    async def _fetch(
        self,
        url: str,
        method: str,
        headers: dict[str, str] | None,
        body: str | None,
        follow_redirects: bool,
        max_redirects: int,
        max_body_size: int,
        timeout: float,
    ) -> FetchOutcome:
        from app.utils.url import normalize_url
        start = time.monotonic()
        steps: list[dict[str, Any]] = []
        current = url
        try:
            attempts = (max_redirects + 1) if follow_redirects else 1
            for _ in range(attempts):
                parsed = urlparse(current)
                host = parsed.hostname or ""
                addresses = await self._guard.resolve_and_check(host)
                pinned = addresses[0]

                req_headers = dict(headers or {})
                req_headers.setdefault("User-Agent", _DEFAULT_UA)
                request = httpx.Request(
                    method.upper(), current, headers=req_headers,
                    content=body.encode("utf-8") if body is not None else None,
                )
                request.extensions["timeout"] = {
                    "connect": self._settings.http_tools_connect_timeout,
                    "read": self._settings.http_tools_read_timeout,
                    "write": self._settings.http_tools_read_timeout,
                    "pool": None,
                    "total": timeout,
                }
                token = pin_address(host, pinned)
                started = time.monotonic()
                try:
                    response = await self._client.send(
                        request, stream=True, follow_redirects=False
                    )
                except httpx.TimeoutException:
                    if self._metrics is not None:
                        self._metrics.inc_upstream("http", False)
                    return FetchOutcome(
                        "Request timed out.", None, None, {}, b"", current, steps, self._ms(start)
                    )
                except httpx.HTTPError:
                    if self._metrics is not None:
                        self._metrics.inc_upstream("http", False)
                    return FetchOutcome(
                        "Request failed.", None, None, {}, b"", current, steps, self._ms(start)
                    )
                finally:
                    unpin_address(token)
                if self._metrics is not None:
                    self._metrics.inc_upstream("http", True)
                    self._metrics.observe_provider(
                        "http", "request", (time.monotonic() - started) * 1000, True
                    )
                try:
                    resp_headers = dict(response.headers)
                    if response.is_redirect and follow_redirects:
                        location = response.headers.get("location", "")
                        if not location:
                            return FetchOutcome("Redirect without a Location header.",
                                                response.status_code, response.reason_phrase,
                                                resp_headers, b"", str(response.url), steps,
                                                self._ms(start))
                        steps.append({"status": response.status_code, "location": location})
                        next_url = normalize_url(urljoin(current, location))
                        current = next_url
                        continue
                    if response.is_redirect and not follow_redirects:
                        return FetchOutcome(None, response.status_code, response.reason_phrase,
                                            resp_headers, b"", str(response.url), steps,
                                            self._ms(start))
                    try:
                        body_bytes = await self._read_limited(response, max_body_size)
                    except ResourceLimitError:
                        return FetchOutcome(
                            "Response exceeds the size limit.", response.status_code,
                            response.reason_phrase, resp_headers, b"", str(response.url),
                            steps, self._ms(start),
                        )
                    except ProviderUnavailableError as exc:
                        return FetchOutcome(str(exc), response.status_code,
                                            response.reason_phrase, resp_headers, b"",
                                            str(response.url), steps, self._ms(start))
                    return FetchOutcome(None, response.status_code, response.reason_phrase,
                                        resp_headers, body_bytes, str(response.url), steps,
                                        self._ms(start))
                finally:
                    await response.aclose()

            return FetchOutcome(
                "Too many redirects.", None, None, {}, b"", current, steps, self._ms(start)
            )
        except SSRFBlockedError:
            return FetchOutcome(
                "The URL resolves to a disallowed (private/internal) address.", None, None,
                {}, b"", current, steps, self._ms(start),
            )
        except ResolutionBlockedError as exc:
            return FetchOutcome(
                str(exc), None, None,
                {}, b"", current, steps, self._ms(start),
            )

    async def _read_limited(self, response: httpx.Response, max_body_size: int) -> bytes:
        chunks: list[bytes] = []
        total = 0
        try:
            async for chunk in response.aiter_bytes(chunk_size=65536):
                total += len(chunk)
                if total > max_body_size:
                    raise ResourceLimitError("Response exceeds the size limit.")
                chunks.append(chunk)
        except httpx.HTTPError as exc:
            raise ProviderUnavailableError(f"Response read failed: {exc}") from exc
        return b"".join(chunks)

    def _error_result(self, url: str, error: str) -> dict[str, Any]:
        return {
            "valid": False,
            "error": error,
            "url": url,
            "final_url": url,
            "status_code": None,
            "reason": None,
            "headers": {},
            "cookies": [],
            "body_preview": None,
            "body_size": 0,
            "body_truncated": False,
            "is_json": False,
            "json_type": None,
            "content_type": None,
            "charset": None,
            "elapsed_ms": None,
            "redirects": [],
            "host": None,
            "ip_addresses": [],
            "ssrf_checked": True,
        }

    @staticmethod
    def _ms(start: float) -> float:
        return round((time.monotonic() - start) * 1000, 1)

    @staticmethod
    def _decode_body(body: bytes, content_type: str) -> str:
        charset = HTTPToolsService._charset(content_type) or "utf-8"
        try:
            return body.decode(charset)
        except (LookupError, UnicodeDecodeError):
            return body.decode("utf-8", errors="replace")

    @staticmethod
    def _charset(content_type: str) -> str | None:
        for part in content_type.split(";")[1:]:
            if "=" in part:
                key, value = part.split("=", 1)
                if key.strip().lower() == "charset":
                    return value.strip().strip('"').lower()
        return None

    def _truncate(self, text: str | None) -> str | None:
        if text is None:
            return None
        limit = 100_000
        if len(text) <= limit:
            return text
        return text[:limit] + "\n… [truncated]"

    @staticmethod
    def _parse_cookies(headers: dict[str, str]) -> list[dict[str, str]]:
        cookies: list[dict[str, str]] = []
        for raw in headers.get("set-cookie", "").split("\n"):
            first = raw.split(";", 1)[0].strip()
            if "=" in first:
                name, value = first.split("=", 1)
                cookies.append({"name": name.strip(), "value": value.strip()})
        return cookies


def _shell_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n")
