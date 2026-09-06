from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final

from app.providers.email.mx_provider import detect_mx_provider

CATEGORY_DISPOSABLE: Final[str] = "disposable"
CATEGORY_PUBLIC_EMAIL: Final[str] = "public_email"
CATEGORY_BUSINESS: Final[str] = "business"


REASON_DISPOSABLE_DOMAIN: Final[str] = "disposable_domain"
REASON_PUBLIC_PROVIDER: Final[str] = "public_email_provider"
REASON_PUBLIC_PROVIDER_MX_UNKNOWN: Final[str] = (
    "public_email_provider_mx_unknown"
)
REASON_BUSINESS_MX_PROVIDER: Final[str] = "business_mx_provider"
REASON_UNKNOWN_PROVIDER: Final[str] = "unknown_email_provider"
REASON_MX_NOT_FOUND: Final[str] = "mx_not_found"
REASON_MX_CHECK_DISABLED: Final[str] = "mx_check_disabled"
REASON_MX_LOOKUP_FAILED: Final[str] = "mx_lookup_failed"


@dataclass(frozen=True, slots=True)
class EmailClassification:
    """
    Deterministic classification result for an email domain.

    `main_category` and `sub_category` intentionally use None when the
    classification cannot be determined confidently.

    Supported main categories:
        - disposable
        - public_email
        - business
        - None
    """

    main_category: str | None
    sub_category: str | None
    reason: str


def _normalize_mx_hosts(
    mx_hosts: Iterable[str] | None,
) -> tuple[str, ...]:
    """
    Normalize MX hostnames for provider detection.

    - ignores non-string values
    - strips whitespace
    - lowercases
    - removes a trailing DNS root dot
    - removes empty values
    - de-duplicates while preserving order
    """
    if mx_hosts is None:
        return ()

    normalized: list[str] = []
    seen: set[str] = set()

    for hostname in mx_hosts:
        if not isinstance(hostname, str):
            continue

        value = hostname.strip().lower().rstrip(".")

        if not value or value in seen:
            continue

        seen.add(value)
        normalized.append(value)

    return tuple(normalized)


def classify_email_detailed(
    *,
    domain: str,
    is_disposable: bool,
    is_public: bool,
    mx_hosts: Iterable[str] | None = None,
    mx_checked: bool = False,
) -> EmailClassification:
    """
    Deterministically classify an email domain.

    Priority:

        1. Disposable
        2. Public/free provider
        3. Known business MX provider
        4. Unknown

    Important:
        An arbitrary MX host does NOT imply a business email.

    Args:
        domain:
            Normalized email domain.

        is_disposable:
            Whether the domain exists in the disposable-domain dataset.

        is_public:
            Whether the domain exists in the public/free email provider
            dataset.

        mx_hosts:
            MX hostnames returned by DNS.

        mx_checked:
            Whether MX lookup was actually attempted/completed.

            False means the caller intentionally did not perform an MX
            lookup.

            True means MX lookup completed and the supplied hosts represent
            the result, including an empty result.
    """
    normalized_hosts = _normalize_mx_hosts(mx_hosts)

    # Disposable always has the highest priority.
    if is_disposable:
        return EmailClassification(
            main_category=CATEGORY_DISPOSABLE,
            sub_category=None,
            reason=REASON_DISPOSABLE_DOMAIN,
        )

    # Public/free providers are classified from the local provider/domain
    # dataset. MX is only used to enrich the provider subtype.
    if is_public:
        if not mx_checked:
            return EmailClassification(
                main_category=CATEGORY_PUBLIC_EMAIL,
                sub_category=None,
                reason=REASON_MX_CHECK_DISABLED,
            )

        provider = detect_mx_provider(normalized_hosts)

        if provider is None:
            return EmailClassification(
                main_category=CATEGORY_PUBLIC_EMAIL,
                sub_category=None,
                reason=REASON_PUBLIC_PROVIDER_MX_UNKNOWN,
            )

        return EmailClassification(
            main_category=CATEGORY_PUBLIC_EMAIL,
            sub_category=provider,
            reason=REASON_PUBLIC_PROVIDER,
        )

    # Non-public domains require MX information before they can be
    # classified as business.
    if not mx_checked:
        return EmailClassification(
            main_category=None,
            sub_category=None,
            reason=REASON_MX_CHECK_DISABLED,
        )

    if not normalized_hosts:
        return EmailClassification(
            main_category=None,
            sub_category=None,
            reason=REASON_MX_NOT_FOUND,
        )

    provider = detect_mx_provider(normalized_hosts)

    # Unknown MX infrastructure must never be treated as business.
    if provider is None:
        return EmailClassification(
            main_category=None,
            sub_category=None,
            reason=REASON_UNKNOWN_PROVIDER,
        )

    return EmailClassification(
        main_category=CATEGORY_BUSINESS,
        sub_category=provider,
        reason=REASON_BUSINESS_MX_PROVIDER,
    )


def classify_email(
    *,
    domain: str,
    is_disposable: bool,
    is_public: bool,
    mx_hosts: Iterable[str] | None = None,
) -> tuple[str | None, str | None]:
    """
    Backward-compatible classification API.

    Returns:
        (main_category, sub_category)

    For detailed classification including reason codes, use
    `classify_email_detailed()`.
    """
    result = classify_email_detailed(
        domain=domain,
        is_disposable=is_disposable,
        is_public=is_public,
        mx_hosts=mx_hosts,
        mx_checked=True,
    )

    return result.main_category, result.sub_category
