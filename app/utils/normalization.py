"""Shared normalization helpers reused across services."""

from __future__ import annotations

from app.core.exceptions import InvalidDomainError, InvalidEmailError
from app.utils.domain import normalize_domain
from app.utils.email import split_email


def normalize_lookup_domain(value: str) -> str:
    """Normalize a bare domain for lookup endpoints."""
    try:
        return normalize_domain(value)
    except InvalidDomainError as exc:
        raise ValueError(str(exc)) from exc


def normalize_lookup_email(value: str) -> str:
    """Normalize an email domain, returning its canonical ASCII form."""
    try:
        return split_email(value)[1]
    except InvalidEmailError as exc:
        raise ValueError(str(exc)) from exc
