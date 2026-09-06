"""URL parsing and safe normalization helpers.

Distinguishes between URL *validation* and URL *intelligence* - we validate and
normalize here without implying anything about the destination's safety.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from app.core.exceptions import InvalidDomainError, InvalidURLError
from app.utils.domain import extract_domain_from_url, normalize_domain
from app.utils.ip import parse_ip

ALLOWED_SCHEMES = frozenset({"http", "https"})


def normalize_url(raw: str) -> str:
    """Normalize a user-supplied URL into an absolute http(s) URL.

    - Accepts schemeless input (e.g. ``example.com``) by defaulting to https.
    - Validates the scheme and hostname.
    - Raises InvalidURLError for unsupported schemes or missing hosts.
    - Does NOT silently alter the path/query semantics.
    """
    value = raw.strip()
    if not value:
        raise InvalidURLError("empty URL")

    has_scheme = "://" in value
    if not has_scheme:
        # Default to https for schemeless input.
        value = "https://" + value
        has_scheme = True

    try:
        parsed = urlparse(value)
    except ValueError as exc:
        raise InvalidURLError(f"malformed URL: {exc}") from exc

    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise InvalidURLError(f"unsupported scheme: {scheme!r}")

    host = parsed.hostname
    if not host:
        raise InvalidURLError("URL has no hostname")

    if parsed.username is not None or parsed.password is not None:
        raise InvalidURLError("URL userinfo is not allowed")

    # Accessing ``port`` triggers ValueError for an out-of-range port; validate
    # it here so a bad port raises a clear error rather than a bare expression.
    try:
        _ = parsed.port
    except ValueError as exc:
        raise InvalidURLError("URL has an invalid port") from exc

    # Literal IP hosts are valid URL hosts and must not be forced through
    # hostname/TLD validation (especially IPv6, which contains colons).
    try:
        parse_ip(host)
    except ValueError:
        try:
            normalize_domain(host)
        except InvalidDomainError as exc:
            raise InvalidURLError(f"invalid hostname: {exc}") from exc

    # Rebuild a canonical absolute URL.
    path = parsed.path or ""
    query = f"?{parsed.query}" if parsed.query else ""
    fragment = f"#{parsed.fragment}" if parsed.fragment else ""
    return f"{scheme}://{parsed.netloc}{path}{query}{fragment}"


def parse_url(raw: str) -> dict[str, Any]:
    """Parse and normalize a URL, returning its structural components."""
    normalized = normalize_url(raw)
    parsed = urlparse(normalized)
    return {
        "url": normalized,
        "scheme": parsed.scheme,
        "host": parsed.hostname,
        "port": parsed.port,
        "path": parsed.path or "",
        "query": parsed.query,
        "fragment": parsed.fragment,
    }


def extract_host(raw: str) -> str:
    """Return the normalized hostname for a URL string."""
    try:
        return extract_domain_from_url(raw)
    except InvalidDomainError as exc:
        raise InvalidURLError(str(exc)) from exc
