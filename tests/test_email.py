"""Tests for the email validation service."""

from __future__ import annotations

from app.services.email_service import EmailValidationService


def _svc(disposable_repo, free_hosts, fake_dns, *, check_mx=True) -> EmailValidationService:
    return EmailValidationService(
        dns_provider=fake_dns,
        disposable_domains=disposable_repo,
        public_email_domains=free_hosts,
        check_mx=check_mx,
    )


async def test_valid_email(disposable_repo, free_hosts, fake_dns) -> None:
    svc = _svc(disposable_repo, free_hosts, fake_dns)
    result = await svc.validate("user@example.com")
    assert result["is_valid"] is True
    assert result["domain"] == "example.com"
    assert result["local_part"] == "user"


async def test_invalid_email(disposable_repo, free_hosts, fake_dns) -> None:
    svc = _svc(disposable_repo, free_hosts, fake_dns)
    result = await svc.validate("not-an-email")
    assert result["is_valid"] is False


async def test_disposable_domain(disposable_repo, free_hosts, fake_dns) -> None:
    svc = _svc(disposable_repo, free_hosts, fake_dns)
    result = await svc.validate("x@guerrillamail.com")
    assert result["is_disposable"] is True


async def test_public_provider(disposable_repo, free_hosts, fake_dns) -> None:
    svc = _svc(disposable_repo, free_hosts, fake_dns)
    result = await svc.validate("u@gmail.com")
    assert result["is_public"] is True
    assert result["is_disposable"] is False


async def test_idn_domain(disposable_repo, free_hosts, fake_dns) -> None:
    svc = _svc(disposable_repo, free_hosts, fake_dns)
    result = await svc.validate("user@münchen.de")
    assert result["is_valid"] is True
    assert result["domain"] == "xn--mnchen-3ya.de"


async def test_mx_check_true(disposable_repo, free_hosts, fake_dns) -> None:
    svc = _svc(disposable_repo, free_hosts, fake_dns, check_mx=True)
    result = await svc.validate("u@gmail.com")
    assert result["mx_exists"] is True


async def test_mx_check_false_for_no_mx(disposable_repo, free_hosts, fake_dns) -> None:
    svc = _svc(disposable_repo, free_hosts, fake_dns, check_mx=True)
    result = await svc.validate("u@nomx.test")
    assert result["mx_exists"] is False


async def test_invalid_email_has_reason(disposable_repo, free_hosts, fake_dns) -> None:
    svc = _svc(disposable_repo, free_hosts, fake_dns)
    result = await svc.validate("not-an-email")
    assert result["is_valid"] is False
    assert result["main_category"] is None
    assert result["sub_category"] is None
    assert isinstance(result["reason"], str) and result["reason"]


async def test_disposable_domain_category(disposable_repo, free_hosts, fake_dns) -> None:
    svc = _svc(disposable_repo, free_hosts, fake_dns, check_mx=True)
    result = await svc.validate("u@example.com")
    # example.com is in the disposable host list -> disposable, sub null.
    assert result["is_disposable"] is True
    assert result["main_category"] == "disposable"
    assert result["sub_category"] is None


async def test_public_provider_category_with_mx(disposable_repo, free_hosts, fake_dns) -> None:
    svc = _svc(disposable_repo, free_hosts, fake_dns, check_mx=True)
    result = await svc.validate("u@gmail.com")
    # gmail.com is a free host and its MX identifies Google Workspace.
    assert result["is_public"] is True
    assert result["mx_exists"] is True
    assert result["main_category"] == "public_email"
    assert result["sub_category"] == "Google Workspace"


async def test_unknown_domain_category_is_null(disposable_repo, free_hosts, fake_dns) -> None:
    svc = _svc(disposable_repo, free_hosts, fake_dns, check_mx=True)
    # nomx.test has no MX and is on no list -> category null (not fabricated).
    result = await svc.validate("u@nomx.test")
    assert result["mx_exists"] is False
    assert result["main_category"] is None
    assert result["sub_category"] is None
