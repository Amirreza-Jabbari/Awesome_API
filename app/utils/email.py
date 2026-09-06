from __future__ import annotations

import re

from app.core.exceptions import (
    InvalidDomainError,
    InvalidEmailError,
)
from app.utils.domain import normalize_domain

MAX_LOCAL_LENGTH = 64
MAX_DOMAIN_LENGTH = 255


_LOCAL_PART_RE = re.compile(
    r"[a-z0-9!#$%&'*+/=?^_`{|}~.\-]+",
    re.IGNORECASE,
)


def split_email(
    email: str,
) -> tuple[str, str]:
    """
    Split and validate an email address.

    Returns:
        (local_part, normalized_domain)

    Important:
        The local part's case is preserved.

        The domain is normalized to canonical ASCII/IDNA form through
        normalize_domain().
    """
    if not isinstance(email, str):
        raise InvalidEmailError(
            "Email must be a string."
        )

    raw = email.strip()

    if not raw:
        raise InvalidEmailError(
            "Email cannot be empty."
        )

    if raw.count("@") != 1:
        raise InvalidEmailError(
            "Email must contain exactly one '@' character."
        )

    local_part, domain_part = raw.rsplit("@", 1)

    local_part = local_part.strip()
    domain_part = domain_part.strip()

    if not local_part:
        raise InvalidEmailError(
            "Email local part cannot be empty."
        )

    if not domain_part:
        raise InvalidEmailError(
            "Email domain cannot be empty."
        )

    if len(local_part) > MAX_LOCAL_LENGTH:
        raise InvalidEmailError(
            "Email local part cannot exceed 64 characters."
        )

    if any(character.isspace() for character in local_part):
        raise InvalidEmailError(
            "Email local part cannot contain whitespace."
        )

    if _LOCAL_PART_RE.fullmatch(local_part) is None:
        raise InvalidEmailError(
            "Email local part contains invalid characters."
        )

    if local_part.startswith(".") or local_part.endswith("."):
        raise InvalidEmailError(
            "Email local part cannot start or end with a dot."
        )

    if ".." in local_part:
        raise InvalidEmailError(
            "Email local part cannot contain consecutive dots."
        )

    if len(domain_part) > MAX_DOMAIN_LENGTH:
        raise InvalidEmailError(
            "Email domain cannot exceed 255 characters."
        )

    if any(character.isspace() for character in domain_part):
        raise InvalidEmailError(
            "Email domain cannot contain whitespace."
        )

    try:
        normalized_domain = normalize_domain(domain_part)

    except InvalidDomainError as exc:
        raise InvalidEmailError(
            "Email contains an invalid domain."
        ) from exc

    return local_part, normalized_domain


def validate_email(
    email: str,
) -> tuple[str, str]:
    """
    Validate an email and return:

        (normalized_email, normalized_domain)

    The local part is preserved exactly after surrounding whitespace
    removal. The domain is canonicalized.
    """
    local_part, normalized_domain = split_email(email)

    return (
        f"{local_part}@{normalized_domain}",
        normalized_domain,
    )


def extract_domain(
    email: str,
) -> str:
    """
    Extract the normalized domain from an email address.
    """
    _, domain = split_email(email)

    return domain


def is_valid(
    email: str,
) -> bool:
    """
    Return True when the email passes local syntax/domain validation.

    This does NOT verify:
        - mailbox existence
        - SMTP deliverability
        - recipient existence
        - whether the domain accepts mail
    """
    try:
        split_email(email)
    except InvalidEmailError:
        return False

    return True


def idn_encode_domain(
    domain: str,
) -> str:
    """
    Backward-compatible IDN helper.

    Domain canonicalization is delegated to normalize_domain() so there
    is one canonical IDNA handling path in the application.
    """
    return normalize_domain(domain)
