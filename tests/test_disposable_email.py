"""Tests for the disposable-email checker service."""

from __future__ import annotations

import pytest
from app.core.exceptions import InvalidEmailError
from app.services.disposable_email_service import DisposableEmailService


def _svc(disposable_repo) -> DisposableEmailService:
    return DisposableEmailService(disposable_repo)


def test_valid_disposable(disposable_repo) -> None:
    svc = _svc(disposable_repo)
    result = svc.check("x@guerrillamail.com")
    assert result.is_disposable is True
    assert result.domain == "guerrillamail.com"


def test_valid_non_disposable(disposable_repo) -> None:
    svc = _svc(disposable_repo)
    result = svc.check("u@gmail.com")
    assert result.is_disposable is False


def test_subdomain_of_disposable(disposable_repo) -> None:
    svc = _svc(disposable_repo)
    result = svc.check("u@sub.guerrillamail.com")
    assert result.is_disposable is True


def test_case_normalization(disposable_repo) -> None:
    svc = _svc(disposable_repo)
    result = svc.check("X@GUERRILLAMAIL.COM")
    assert result.is_disposable is True


def test_invalid_email_raises(disposable_repo) -> None:
    svc = _svc(disposable_repo)
    with pytest.raises(InvalidEmailError):
        svc.check("not-an-email")
