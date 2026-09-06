"""Tests for phone number validation."""

from __future__ import annotations

from app.services.phone_service import PhoneValidationService


def _svc() -> PhoneValidationService:
    return PhoneValidationService()


def test_international_valid() -> None:
    result = _svc().validate("+14155552671")
    assert result.is_valid is True
    assert result.country_code == 1


def test_national_with_country() -> None:
    result = _svc().validate("020 7946 0958", country="GB")
    assert result.is_valid is True
    assert result.country_code == 44


def test_invalid_number() -> None:
    result = _svc().validate("+1234notanumber")
    assert result.is_valid is False
    assert result.reason is not None


def test_possible_but_not_valid() -> None:
    # A number with a valid format but an unassigned/not-valid value.
    result = _svc().validate("+55 11 00000-0000")
    assert result.is_valid is False


def test_empty_number() -> None:
    result = _svc().validate("   ")
    assert result.is_valid is False
    assert result.reason == "empty number"


def test_different_countries() -> None:
    us = _svc().validate("+14155552671")
    de = _svc().validate("+49 30 901820")
    assert us.country_code == 1
    assert de.country_code == 49


def test_formatting_fields() -> None:
    result = _svc().validate("+14155552671")
    assert result.format_international is not None
    assert result.format_e164 is not None
    assert result.is_formatted_properly is True
