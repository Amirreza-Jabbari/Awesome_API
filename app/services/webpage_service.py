"""Webpage metadata extraction service.

Security-critical: this endpoint is a potential SSRF vector. Guards:

* hostname/IP format validated up front
* every hop (including each redirect) is DNS-resolved and rejected when any
  address is private/loopback/link-local/CGNAT/metadata
* response body is streamed and capped at ``WEBPAGE_MAX_RESPONSE_SIZE``
* total/connect/read timeouts and a redirect limit are enforced
* a post-fetch re-resolution re-verifies the peer so classic DNS-rebinding
  attacks are harder to succeed
* only HTML content types are parsed; JS is never executed and no browser is
  launched
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from app.core.config import Settings
from app.core.exceptions import (
    ProviderTimeoutError,
    ProviderUnavailableError,
    ResourceLimitError,
    SSRFBlockedError,
)
from app.providers.web.ssrf import SSRFGuard, pin_address, unpin_address

logger = logging.getLogger(__name__)

_HTML_CONTENT_TYPES = ("text/html", "application/xhtml+xml")


@dataclass(slots=True)
class WebFetchResult:
    url: str
    status_code: int
    headers: dict[str, str]
    body: bytes
    content_type: str


class WebpageService:
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

    async def extract(self, raw_url: str) -> dict[str, Any]:
        from app.utils.url import normalize_url

        url = normalize_url(raw_url)
        result = await self.fetch(url)
        return self._parse_page(result.url, result.body, result.content_type)

    async def fetch(self, raw_url: str) -> WebFetchResult:
        """Securely fetch a URL and expose response metadata for other web tools.

        The same SSRF policy, redirect handling, size cap, and timeout controls
        used by webpage metadata extraction are reused by all live web analyzers.
        """
        from app.utils.url import normalize_url
        url = normalize_url(raw_url)
        return await self._fetch_with_redirects(url)

    async def _fetch_with_redirects(self, url: str) -> WebFetchResult:
        current = url
        for step in range(self._settings.webpage_max_redirects + 1):
            result = await self._fetch_once(current)
            if result.status_code in (301, 302, 303, 307, 308):
                location = result.headers.get("location", "")
                try:
                    from app.utils.url import normalize_url

                    # Location may be absolute, protocol-relative, or a
                    # relative path. urljoin preserves the redirect semantics
                    # instead of incorrectly turning "/login" into an
                    # https:///login URL.
                    current = normalize_url(urljoin(current, location))
                except Exception as exc:
                    raise SSRFBlockedError(f"Invalid redirect target: {location}") from exc
                if step == self._settings.webpage_max_redirects:
                    raise ResourceLimitError("Too many redirects.")
                continue
            return result
        raise ResourceLimitError("Too many redirects.")

    async def _fetch_once(self, url: str) -> WebFetchResult:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        addresses = await self._guard.resolve_and_check(host)
        pinned = addresses[0]

        connect_timeout = self._settings.webpage_connect_timeout
        read_timeout = self._settings.webpage_read_timeout
        total_timeout = self._settings.webpage_timeout

        headers = {
            "User-Agent": self._settings.webpage_user_agent,
            "Accept": "text/html,application/xhtml+xml;q=0.9,text/plain;q=0.5",
            "Accept-Language": "en",
        }
        request = httpx.Request("GET", url, headers=headers)
        request.extensions["timeout"] = {
            "connect": connect_timeout,
            "read": read_timeout,
            "write": read_timeout,
            "pool": None,
            "total": total_timeout,
        }
        token = pin_address(host, pinned)
        started = time.perf_counter()
        try:
            response = await self._client.send(request, stream=True, follow_redirects=False)
        except httpx.TimeoutException as exc:
            if self._metrics is not None:
                self._metrics.inc_upstream("webpage", False)
            raise ProviderTimeoutError("Webpage fetch timed out") from exc
        except httpx.HTTPError as exc:
            if self._metrics is not None:
                self._metrics.inc_upstream("webpage", False)
            raise ProviderUnavailableError("Webpage fetch failed.") from exc
        finally:
            unpin_address(token)
        if self._metrics is not None:
            self._metrics.inc_upstream("webpage", True)
            self._metrics.observe_provider(
                "webpage", "fetch", (time.perf_counter() - started) * 1000, True
            )

        try:
            # Post-fetch re-resolution to defeat racing DNS-rebinding.
            await self._verify_peer(host)

            if response.is_redirect or response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("location", "")
                if not location:
                    raise ProviderUnavailableError("Redirect without a location header")
                return WebFetchResult(
                    url=str(response.url),
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    body=b"",
                    content_type="",
                )

            content_type = response.headers.get("content-type", "")
            body = await self._read_limited(response)
        finally:
            await response.aclose()

        return WebFetchResult(
            url=str(response.url),
            status_code=response.status_code,
            headers=dict(response.headers),
            body=body,
            content_type=content_type,
        )

    async def _read_limited(self, response: httpx.Response) -> bytes:
        """Stream the response body, aborting at the configured size cap."""
        max_size = self._settings.webpage_max_response_size
        chunks: list[bytes] = []
        total = 0
        try:
            async for chunk in response.aiter_bytes(chunk_size=65536):
                total += len(chunk)
                if total > max_size:
                    raise ResourceLimitError("Webpage response exceeds the size limit.")
                chunks.append(chunk)
        except httpx.HTTPError as exc:
            raise ProviderUnavailableError(f"Webpage read failed: {exc}") from exc
        return b"".join(chunks)

    async def _verify_peer(self, host: str) -> None:
        """Re-resolve the host and reject if any address is blocked."""
        try:
            await self._guard.resolve_and_check(host)
        except SSRFBlockedError:
            raise
        except Exception:
            # Resolution failures after a successful fetch are tolerated - the
            # fetch itself already succeeded and was checked pre-connect.
            logger.debug("post-fetch re-resolution failed for %s", host)

    def _parse_page(self, url: str, body: bytes, content_type: str) -> dict[str, Any]:
        from app.utils.domain import extract_domain_from_url

        parsed = urlparse(url)
        domain_ct: str | None = None
        try:
            domain_ct = extract_domain_from_url(url)
        except Exception:
            domain_ct = None

        query_params: dict[str, str] = {}
        if parsed.query:
            for key, values in parse_qs(parsed.query, keep_blank_values=True).items():
                query_params[key] = values[0] if values else ""

        base: dict[str, Any] = {
            "url": url,
            "domain": domain_ct or "",
            "url_path": parsed.path or "",
            "url_parameters": query_params,
            "page_title": None,
            "page_description": None,
            "meta_tags": {},
            "favicon": None,
            "final_url": url,
        }

        lowered_ct = content_type.lower()
        is_html = any(ct in lowered_ct for ct in _HTML_CONTENT_TYPES) or not lowered_ct
        if not is_html or not body:
            return base

        try:
            soup = BeautifulSoup(body, "lxml")
        except Exception:
            soup = BeautifulSoup(body, "html.parser")

        title_tag = soup.find("title")
        if title_tag and title_tag.string:
            base["page_title"] = title_tag.string.strip()

        meta_tags: dict[str, str] = {}
        for meta in soup.find_all("meta"):
            name_or_prop = meta.get("name") or meta.get("property")
            content = meta.get("content")
            if name_or_prop and content is not None:
                meta_tags[str(name_or_prop)] = str(content)
        base["meta_tags"] = meta_tags
        base["page_description"] = meta_tags.get("description")

        favicon = self._extract_favicon(soup, url)
        base["favicon"] = favicon
        return base

    @staticmethod
    def _extract_favicon(soup: BeautifulSoup, url: str) -> str | None:
        link = soup.find("link", rel=lambda v: v and "icon" in " ".join(v).lower())
        if link and link.get("href"):
            href = str(link["href"]).strip()
            if href.startswith("//"):
                href = "https:" + href
            return href
        # Fallback: /favicon.ico on the origin - do not fetch it, just report.
        parsed = urlparse(url)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}/favicon.ico"
        return None
