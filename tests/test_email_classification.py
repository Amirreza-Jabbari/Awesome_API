"""Tests for the local email classification provider."""

from __future__ import annotations

from app.providers.email.classification import classify_email


def test_disposable_takes_priority() -> None:
    main, sub = classify_email(
        domain="example.com",
        is_disposable=True,
        is_public=True,
        mx_hosts=["aspmx.l.google.com"],
    )
    assert main == "disposable"
    assert sub is None


def test_public_email_known_provider() -> None:
    main, sub = classify_email(
        domain="gmail.com",
        is_disposable=False,
        is_public=True,
        mx_hosts=["aspmx.l.google.com"],
    )
    assert main == "public_email"
    assert sub == "Google Workspace"


def test_public_email_unknown_provider() -> None:
    main, sub = classify_email(
        domain="example.net",
        is_disposable=False,
        is_public=True,
        mx_hosts=["mx.notgoogle.com"],
    )
    assert main == "public_email"
    assert sub is None


def test_business_domain_known_provider() -> None:
    main, sub = classify_email(
        domain="corp.example",
        is_disposable=False,
        is_public=False,
        mx_hosts=["microsoft-com.mail.protection.outlook.com"],
    )
    assert main == "business"
    assert sub == "Microsoft 365"


def test_unknown_returns_nulls() -> None:
    main, sub = classify_email(
        domain="example.net",
        is_disposable=False,
        is_public=False,
        mx_hosts=["mx.example.net"],
    )
    assert main is None
    assert sub is None


def test_no_mx_returns_nulls() -> None:
    main, sub = classify_email(
        domain="example.net",
        is_disposable=False,
        is_public=False,
        mx_hosts=[],
    )
    assert main is None
    assert sub is None
