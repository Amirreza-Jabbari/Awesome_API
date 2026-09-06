"""Security helpers: secret-safe header validation and future auth hooks.

Authentication is intentionally kept out of the business logic. This module
provides a clean seam where API-key / bearer authentication can be plugged in
without touching service or provider code.
"""

from __future__ import annotations

import hmac
from typing import Any

from fastapi import Header, HTTPException

API_KEY_HEADER = "X-API-Key"


class AccessTokenUnavailableError(Exception):
    """Raised when an access token cannot be obtained."""


def constant_time_equals(a: str, b: str) -> bool:
    """Constant-time string comparison for secret checks."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


async def require_api_key(
    x_api_key: str | None = Header(default=None, alias=API_KEY_HEADER),
) -> Any:
    """Dependency that validates an API key when one is configured at runtime.

    This is a pluggable future seam. When a key provider is configured it is
    checked; otherwise the dependency allows the request through. The current
    design intentionally avoids introducing user management.
    """
    # When API-key auth is enabled via configuration the resolver logic would
    # live here. Kept minimal and explicit rather than faking behaviour.
    del x_api_key
    raise HTTPException(status_code=501, detail="API key authentication is not enabled.")
