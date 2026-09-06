"""Tests for password generation."""

from __future__ import annotations

import string

import pytest
from app.core.exceptions import ResourceLimitError
from app.schemas.password import PasswordGenerateRequest
from app.services.password_service import (
    DIGITS,
    LOWER,
    SPECIALS,
    UPPER,
    PasswordService,
    generate_password,
)


@pytest.fixture
def service() -> PasswordService:
    return PasswordService()


def _sets(password: str) -> dict[str, bool]:
    return {
        "upper": any(c in UPPER for c in password),
        "lower": any(c in LOWER for c in password),
        "digit": any(c in DIGITS for c in password),
        "special": any(c in SPECIALS for c in password),
    }


def test_default_length(service: PasswordService) -> None:
    req = PasswordGenerateRequest()
    pw = service.generate(req)
    assert len(pw) == req.length == 16


def test_custom_length(service: PasswordService) -> None:
    req = PasswordGenerateRequest(length=32)
    pw = service.generate(req)
    assert len(pw) == 32


def test_exclude_numbers(service: PasswordService) -> None:
    req = PasswordGenerateRequest(exclude_numbers=True, min_numbers=0)
    pw = service.generate(req)
    assert not any(c in DIGITS for c in pw)


def test_exclude_specials(service: PasswordService) -> None:
    req = PasswordGenerateRequest(exclude_special_chars=True, min_specials=0)
    pw = service.generate(req)
    assert not any(c in SPECIALS for c in pw)


def test_category_guarantees(service: PasswordService) -> None:
    for _ in range(50):
        req = PasswordGenerateRequest()
        pw = service.generate(req)
        cats = _sets(pw)
        assert cats["upper"] and cats["lower"] and cats["digit"] and cats["special"]


def test_impossible_configuration_raises() -> None:
    # Service-layer function raises when required categories exceed length.
    with pytest.raises(ResourceLimitError):
        generate_password(length=4, min_upper=2, min_lower=2, min_numbers=2, min_specials=2)


def test_length_out_of_range_raises() -> None:
    with pytest.raises(ResourceLimitError):
        generate_password(length=3)
    with pytest.raises(ResourceLimitError):
        generate_password(length=999)


def test_all_categories_disabled_falls_back_alphanumeric() -> None:
    pw = generate_password(
        length=12,
        exclude_numbers=True,
        exclude_special_chars=True,
        min_numbers=0,
        min_specials=0,
    )
    assert len(pw) == 12
    assert pw.isalnum()
    assert not any(c in SPECIALS for c in pw)
    assert not any(c in DIGITS for c in pw)


def test_generated_password_in_alphabet(service: PasswordService) -> None:
    req = PasswordGenerateRequest(length=64)
    pw = service.generate(req)
    allowed = set(string.ascii_letters + string.digits + SPECIALS)
    assert set(pw) <= allowed
