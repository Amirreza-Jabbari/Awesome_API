"""Disposable email checking service."""

from __future__ import annotations

from dataclasses import dataclass

from app.repositories.host_lists import DisposableEmailRepository
from app.utils.domain import normalize_domain
from app.utils.email import split_email


@dataclass(slots=True)
class DisposableEmailResult:
    email: str
    domain: str
    is_disposable: bool


class DisposableEmailService:
    """Checks whether a domain is a known disposable-email provider."""

    def __init__(self, repository: DisposableEmailRepository) -> None:
        self._repository = repository

    def check(self, email: str) -> DisposableEmailResult:
        _, domain = split_email(email)  # raises InvalidEmailError
        normalized = normalize_domain(domain)
        is_disposable = self._repository.is_disposable(normalized)
        return DisposableEmailResult(
            email=email.strip(),
            domain=normalized,
            is_disposable=is_disposable,
        )
