from __future__ import annotations

from typing import Any

from app.core.exceptions import (
    DNSLookupError,
    DNSNoDataError,
    DNSNXDomainError,
    DNSTimeoutError,
    InvalidEmailError,
)
from app.providers.email.classification import (
    REASON_MX_LOOKUP_FAILED,
    EmailClassification,
    classify_email_detailed,
)
from app.utils.email import split_email


class EmailValidationService:
    """
    Email syntax and domain validation/classification service.

    This service does NOT verify mailbox existence or SMTP deliverability.

    Semantic contract:

        is_valid:
            Syntax/domain validation only.

        mx_exists:
            True  -> usable MX records confirmed.
            False -> MX lookup completed and no usable MX records found.
            None  -> MX status could not be determined.

        classification:
            disposable
            public_email
            business
            None
    """

    def __init__(
        self,
        *,
        dns_provider: Any,
        disposable_domains: Any,
        public_email_domains: Any,
        check_mx: bool = True,
    ) -> None:
        self._dns_provider = dns_provider
        self._disposable_domains = disposable_domains
        self._public_email_domains = public_email_domains
        self._check_mx = check_mx

    async def validate(
        self,
        email: str,
    ) -> dict[str, Any]:
        """
        Validate and classify an email address.
        """
        raw_email = email

        try:
            local_part, normalized_domain = split_email(
                raw_email
            )

        except InvalidEmailError as exc:
            return {
                "email": raw_email.strip()
                if isinstance(raw_email, str)
                else raw_email,
                "domain": None,
                "local_part": None,
                "is_valid": False,
                "is_disposable": False,
                "is_public": False,
                "mx_exists": None,
                "main_category": None,
                "sub_category": None,
                "reason": exc.message,
            }

        is_disposable = self._is_disposable_domain(
            normalized_domain
        )

        is_public = self._is_public_domain(
            normalized_domain
        )

        if not self._check_mx:
            classification = classify_email_detailed(
                domain=normalized_domain,
                is_disposable=is_disposable,
                is_public=is_public,
                mx_hosts=None,
                mx_checked=False,
            )

            return self._build_result(
                local_part=local_part,
                normalized_domain=normalized_domain,
                is_disposable=is_disposable,
                is_public=is_public,
                mx_exists=None,
                classification=classification,
            )

        try:
            mx_data = await self._dns_provider.get_mx_hosts(
                normalized_domain
            )

        except DNSNoDataError:
            # DNS completed successfully but there are no MX records.
            classification = classify_email_detailed(
                domain=normalized_domain,
                is_disposable=is_disposable,
                is_public=is_public,
                mx_hosts=(),
                mx_checked=True,
            )

            return self._build_result(
                local_part=local_part,
                normalized_domain=normalized_domain,
                is_disposable=is_disposable,
                is_public=is_public,
                mx_exists=False,
                classification=classification,
            )

        except (
            DNSNXDomainError,
            DNSTimeoutError,
            DNSLookupError,
        ):
            # DNS status cannot be determined.

            classification = self._classify_after_mx_failure(
                normalized_domain=normalized_domain,
                is_disposable=is_disposable,
                is_public=is_public,
            )

            return self._build_result(
                local_part=local_part,
                normalized_domain=normalized_domain,
                is_disposable=is_disposable,
                is_public=is_public,
                mx_exists=None,
                classification=classification,
            )

        # A successful MX lookup returning no records is a valid
        # "no MX" result, not a DNS failure.
        mx_hosts = [
            item.hostname
            for item in mx_data
            if getattr(item, "hostname", None)
        ]

        mx_exists = bool(mx_hosts)

        classification = classify_email_detailed(
            domain=normalized_domain,
            is_disposable=is_disposable,
            is_public=is_public,
            mx_hosts=mx_hosts,
            mx_checked=True,
        )

        return self._build_result(
            local_part=local_part,
            normalized_domain=normalized_domain,
            is_disposable=is_disposable,
            is_public=is_public,
            mx_exists=mx_exists,
            classification=classification,
        )

    def _classify_after_mx_failure(
        self,
        *,
        normalized_domain: str,
        is_disposable: bool,
        is_public: bool,
    ) -> EmailClassification:
        """
        Classify using local information after an MX lookup failure.

        Disposable/public signals remain useful even when DNS is
        unavailable.

        Unknown domains receive the technical MX failure reason.
        """
        if is_disposable:
            return classify_email_detailed(
                domain=normalized_domain,
                is_disposable=True,
                is_public=is_public,
                mx_hosts=None,
                mx_checked=False,
            )

        if is_public:
            return classify_email_detailed(
                domain=normalized_domain,
                is_disposable=False,
                is_public=True,
                mx_hosts=None,
                mx_checked=False,
            )

        # Unknown domain + failed MX lookup needs to retain the
        # distinction between "unknown provider" and "DNS unavailable".
        return EmailClassification(
            main_category=None,
            sub_category=None,
            reason=REASON_MX_LOOKUP_FAILED,
        )

    def _build_result(
        self,
        *,
        local_part: str,
        normalized_domain: str,
        is_disposable: bool,
        is_public: bool,
        mx_exists: bool | None,
        classification: EmailClassification,
    ) -> dict[str, Any]:
        """
        Build the stable API/service result.
        """
        return {
            "email": f"{local_part}@{normalized_domain}",
            "domain": normalized_domain,
            "local_part": local_part,
            "is_valid": True,
            "is_disposable": is_disposable,
            "is_public": is_public,
            "mx_exists": mx_exists,
            "main_category": classification.main_category,
            "sub_category": classification.sub_category,
            "reason": classification.reason,
        }

    def _is_disposable_domain(
        self,
        domain: str,
    ) -> bool:
        """
        Check the disposable-domain repository/dataset.

        Supports the existing repository-style API while keeping this
        service independent from its concrete implementation.
        """
        checker = self._disposable_domains

        if hasattr(checker, "contains"):
            return bool(checker.contains(domain))

        if hasattr(checker, "is_disposable"):
            return bool(checker.is_disposable(domain))

        try:
            if domain in checker:
                return True
        except TypeError:
            pass

        if isinstance(checker, (set, frozenset, list, tuple)):
            return domain in checker

        return False

    def _is_public_domain(
        self,
        domain: str,
    ) -> bool:
        """
        Check the public/free email-domain repository/dataset.
        """
        checker = self._public_email_domains

        if hasattr(checker, "contains"):
            return bool(checker.contains(domain))

        if hasattr(checker, "is_public"):
            return bool(checker.is_public(domain))

        try:
            if domain in checker:
                return True
        except TypeError:
            pass

        if isinstance(checker, (set, frozenset, list, tuple)):
            return domain in checker

        return False
