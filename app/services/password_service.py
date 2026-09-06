"""Cryptographically secure password generation.

Uses ``secrets`` and ``secrets.randbelow`` to avoid modulo bias. At least one
character from every (enabled, required) category is guaranteed. Generated
passwords are never logged, persisted or cached.
"""

from __future__ import annotations

import secrets
import string

from app.core.exceptions import ResourceLimitError
from app.schemas.password import PasswordGenerateRequest

UPPER = string.ascii_uppercase
LOWER = string.ascii_lowercase
DIGITS = string.digits
SPECIALS = "!@#$%^&*()"

DEFAULT_LENGTH = 16
MAX_LENGTH = 256
MIN_LENGTH = 4


def _random_choice(bucket: str) -> str:
    # secrets.choice uses secrets.randbelow internally and is uniform.
    return secrets.choice(bucket)


def generate_password(
    length: int = DEFAULT_LENGTH,
    exclude_numbers: bool = False,
    exclude_special_chars: bool = False,
    min_upper: int = 1,
    min_lower: int = 1,
    min_numbers: int = 1,
    min_specials: int = 1,
) -> str:
    """Generate a cryptographically secure random password.

    Character-set feasibility is validated before generation. Credentials are
    returned only to the caller; they are never logged/persisted.
    """
    if not MIN_LENGTH <= length <= MAX_LENGTH:
        raise ResourceLimitError("Password length out of range.")

    buckets: list[str] = []
    requirements: list[int] = []
    if min_upper > 0:
        buckets.append(UPPER)
        requirements.append(min_upper)
    if min_lower > 0:
        buckets.append(LOWER)
        requirements.append(min_lower)
    if not exclude_numbers and min_numbers > 0:
        buckets.append(DIGITS)
        requirements.append(min_numbers)
    if not exclude_special_chars and min_specials > 0:
        buckets.append(SPECIALS)
        requirements.append(min_specials)

    if not buckets:
        # All categories disabled/zero-required: fall back to a safe default
        # pool (alphanumerics) which is always available.
        buckets = [UPPER + LOWER + DIGITS]
        requirements = [length]

    available_pool = "".join(buckets)
    if not available_pool:
        raise ResourceLimitError("No character set available for password.")

    required_total = sum(requirements)
    if required_total > length:
        raise ResourceLimitError("Password length is too short for the requested character mix.")

    # Guarantee at least one char from each requested category.
    chars = [
        _random_choice(bucket)
        for bucket, req in zip(buckets, requirements, strict=True)
        for _ in range(req)
    ]
    remaining = length - len(chars)
    if remaining > 0:
        chars.extend(_random_choice(available_pool) for _ in range(remaining))

    # secrets-based Fisher-Yates shuffle for a uniform final arrangement.
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]

    password = "".join(chars)
    # Post-conditions (best-effort assertions), never raises on valid input.
    for bucket, req in zip(buckets, requirements, strict=True):
        if req > 0 and not any(ch in bucket for ch in password):
            raise RuntimeError("password category guarantee violated")
    return password


def validate_request(req: PasswordGenerateRequest) -> None:
    """Validate a schema request against service-level constraints."""
    if req.length < MIN_LENGTH or req.length > MAX_LENGTH:
        raise ResourceLimitError("Password length out of range.")
    if req.exclude_numbers and req.exclude_special_chars and req.min_numbers + req.min_specials > 0:
        raise ResourceLimitError("Required characters excluded.")
    required = req.min_upper + req.min_lower
    if not req.exclude_numbers:
        required += req.min_numbers
    if not req.exclude_special_chars:
        required += req.min_specials
    if required > req.length:
        raise ResourceLimitError("Requested character mix exceeds password length.")


class PasswordService:
    """Stateless password generation service."""

    def generate(self, req: PasswordGenerateRequest) -> str:
        validate_request(req)
        return generate_password(
            length=req.length,
            exclude_numbers=req.exclude_numbers,
            exclude_special_chars=req.exclude_special_chars,
            min_upper=req.min_upper,
            min_lower=req.min_lower,
            min_numbers=req.min_numbers,
            min_specials=req.min_specials,
        )
