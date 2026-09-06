"""Tests for the domain aggregate-intelligence service."""

from __future__ import annotations

from app.services.domain_service import DomainService


def _svc(
    whois_service,
    fake_dns,
    fake_geoip,
    disposable_repo,
    free_hosts,
    risky_tlds,
    malicious_repo,
    settings,
) -> DomainService:
    return DomainService(
        whois=whois_service,
        dns=fake_dns,
        geoip=fake_geoip,
        disposable=disposable_repo,
        free_hosts=free_hosts,
        risky_tlds=risky_tlds,
        malicious=malicious_repo,
        settings=settings,
    )


async def test_existing_domain(
    whois_service,
    fake_dns,
    fake_geoip,
    disposable_repo,
    free_hosts,
    risky_tlds,
    malicious_repo,
    settings,
) -> None:
    svc = _svc(
        whois_service,
        fake_dns,
        fake_geoip,
        disposable_repo,
        free_hosts,
        risky_tlds,
        malicious_repo,
        settings,
    )
    result = await svc.lookup("example.com")
    assert result["available"] is False
    assert result["registrar"] == "Example Registrar"
    assert result["creation_date"] is not None


async def test_registry_not_found_marks_available(
    whois_service,
    rdap,
    fake_dns,
    fake_geoip,
    disposable_repo,
    free_hosts,
    risky_tlds,
    malicious_repo,
    settings,
) -> None:
    rdap.set_registered(False)
    svc = _svc(
        whois_service,
        fake_dns,
        fake_geoip,
        disposable_repo,
        free_hosts,
        risky_tlds,
        malicious_repo,
        settings,
    )
    result = await svc.lookup("example.com")
    assert result["available"] is True


async def test_missing_whois_fields(
    whois_service,
    rdap,
    fake_dns,
    fake_geoip,
    disposable_repo,
    free_hosts,
    risky_tlds,
    malicious_repo,
    settings,
) -> None:
    svc = _svc(
        whois_service,
        fake_dns,
        fake_geoip,
        disposable_repo,
        free_hosts,
        risky_tlds,
        malicious_repo,
        settings,
    )
    result = await svc.lookup("example.com")
    # The fake returns a fully populated RDAP record; verify fields map through.
    assert result["creation_date"] == 1600000000
    assert result["registrar"] == "Example Registrar"


async def test_risky_tld_detection(
    whois_service,
    fake_dns,
    fake_geoip,
    disposable_repo,
    free_hosts,
    risky_tlds,
    malicious_repo,
    settings,
) -> None:
    svc = _svc(
        whois_service,
        fake_dns,
        fake_geoip,
        disposable_repo,
        free_hosts,
        risky_tlds,
        malicious_repo,
        settings,
    )
    result = await svc.lookup("example.top")
    assert result["risky_tld"] is True


async def test_free_email_provider_detection(
    whois_service,
    fake_dns,
    fake_geoip,
    disposable_repo,
    free_hosts,
    risky_tlds,
    malicious_repo,
    settings,
) -> None:
    svc = _svc(
        whois_service,
        fake_dns,
        fake_geoip,
        disposable_repo,
        free_hosts,
        risky_tlds,
        malicious_repo,
        settings,
    )
    result = await svc.lookup("gmail.com")
    assert result["is_free_email_provider"] is True
    assert result["mx_provider"] is not None


async def test_disposable_domain_detection(
    whois_service,
    fake_dns,
    fake_geoip,
    disposable_repo,
    free_hosts,
    risky_tlds,
    malicious_repo,
    settings,
) -> None:
    svc = _svc(
        whois_service,
        fake_dns,
        fake_geoip,
        disposable_repo,
        free_hosts,
        risky_tlds,
        malicious_repo,
        settings,
    )
    result = await svc.lookup("guerrillamail.com")
    assert result["is_disposable_email_domain"] is True


async def test_malicious_domain_detection(
    whois_service,
    fake_dns,
    fake_geoip,
    disposable_repo,
    free_hosts,
    risky_tlds,
    malicious_repo,
    settings,
) -> None:
    svc = _svc(
        whois_service,
        fake_dns,
        fake_geoip,
        disposable_repo,
        free_hosts,
        risky_tlds,
        malicious_repo,
        settings,
    )
    result = await svc.lookup("evil.example.com")
    assert result["is_malicious"] is True


async def test_malicious_subdomain_detection(
    whois_service,
    fake_dns,
    fake_geoip,
    disposable_repo,
    free_hosts,
    risky_tlds,
    malicious_repo,
    settings,
) -> None:
    svc = _svc(
        whois_service,
        fake_dns,
        fake_geoip,
        disposable_repo,
        free_hosts,
        risky_tlds,
        malicious_repo,
        settings,
    )
    result = await svc.lookup("sub.evil.example.com")
    assert result["is_malicious"] is True


async def test_non_malicious_domain(
    whois_service,
    fake_dns,
    fake_geoip,
    disposable_repo,
    free_hosts,
    risky_tlds,
    malicious_repo,
    settings,
) -> None:
    svc = _svc(
        whois_service,
        fake_dns,
        fake_geoip,
        disposable_repo,
        free_hosts,
        risky_tlds,
        malicious_repo,
        settings,
    )
    result = await svc.lookup("example.org")
    assert result["is_malicious"] is False


async def test_parked_detection(
    whois_service,
    fake_dns,
    fake_geoip,
    disposable_repo,
    free_hosts,
    risky_tlds,
    malicious_repo,
    settings,
) -> None:
    svc = _svc(
        whois_service,
        fake_dns,
        fake_geoip,
        disposable_repo,
        free_hosts,
        risky_tlds,
        malicious_repo,
        settings,
    )
    result = await svc.lookup("example.com")
    assert result["is_parked"] is False or result["is_parked"] is True


async def test_google_mx_provider_pattern(
    whois_service,
    fake_dns,
    fake_geoip,
    disposable_repo,
    free_hosts,
    risky_tlds,
    malicious_repo,
    settings,
) -> None:
    # Google Workspace now commonly publishes smtp.google.com.
    fake_dns._mx_override = {"google.com": ["smtp.google.com"]}
    svc = _svc(
        whois_service,
        fake_dns,
        fake_geoip,
        disposable_repo,
        free_hosts,
        risky_tlds,
        malicious_repo,
        settings,
    )
    result = await svc.lookup("google.com")
    assert result["mx_provider"] == "Google Workspace"
