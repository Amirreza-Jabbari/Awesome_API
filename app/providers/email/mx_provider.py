from __future__ import annotations

import re
from dataclasses import dataclass

GOOGLE_WORKSPACE = "Google Workspace"
MICROSOFT_365 = "Microsoft 365"
PROTON_MAIL = "Proton Mail"
ZOHO_MAIL = "Zoho Mail"
FASTMAIL = "Fastmail"
YAHOO = "Yahoo"
ICLOUD_MAIL = "iCloud Mail"
NAMECHEAP_PRIVATE_EMAIL = "Namecheap Private Email"


@dataclass(frozen=True, slots=True)
class MXPattern:
    """
    A provider and its deterministic MX hostname patterns.
    """

    name: str
    patterns: tuple[re.Pattern[str], ...]


_MX_RULES: tuple[MXPattern, ...] = (
    MXPattern(
        name=GOOGLE_WORKSPACE,
        patterns=(
            re.compile(
                r"^(?:aspmx|googlemail)(?:\.l)?\.google\.com$",
                re.IGNORECASE,
            ),
            # Google Workspace also commonly publishes smtp.google.com.
            re.compile(
                r"^smtp\.google\.com$",
                re.IGNORECASE,
            ),
        ),
    ),
    MXPattern(
        name=MICROSOFT_365,
        patterns=(
            # Standard Microsoft 365 Exchange Online MX:
            # <tenant>.mail.protection.outlook.com
            re.compile(
                r"^[a-z0-9-]+\.mail\.protection\.outlook\.com$",
                re.IGNORECASE,
            ),
            # Keep support for known legacy/general Microsoft MX forms.
            re.compile(
                r"^(?:protection|outlook|office365)\.outlook\.com$",
                re.IGNORECASE,
            ),
        ),
    ),
    MXPattern(
        name=PROTON_MAIL,
        patterns=(
            re.compile(
                r"^(?:mail|mailsec\d*|protonmail)\.protonmail\.ch$",
                re.IGNORECASE,
            ),
            re.compile(
                r"^[a-z0-9-]+\.protonmail\.ch$",
                re.IGNORECASE,
            ),
            re.compile(
                r"^[a-z0-9-]+\.proton\.ch$",
                re.IGNORECASE,
            ),
            re.compile(
                r"^[a-z0-9-]+\.proton\.com$",
                re.IGNORECASE,
            ),
        ),
    ),
    MXPattern(
        name=ZOHO_MAIL,
        patterns=(
            re.compile(
                r"^[a-z0-9-]+\.zoho\.(?:com|eu|in)$",
                re.IGNORECASE,
            ),
        ),
    ),
    MXPattern(
        name=FASTMAIL,
        patterns=(
            re.compile(
                r"^[a-z0-9-]+\.fastmail\.(?:com|fm|net)$",
                re.IGNORECASE,
            ),
            re.compile(
                r"^in\d+-smtp\.messagingengine\.com$",
                re.IGNORECASE,
            ),
            re.compile(
                r"^out\d+-smtp\.messagingengine\.com$",
                re.IGNORECASE,
            ),
            re.compile(
                r"^mx\d+\.messagingengine\.com$",
                re.IGNORECASE,
            ),
        ),
    ),
    MXPattern(
        name=YAHOO,
        patterns=(
            re.compile(
                r"^[a-z0-9-]+\.yahoodns\.net$",
                re.IGNORECASE,
            ),
        ),
    ),
    MXPattern(
        name=ICLOUD_MAIL,
        patterns=(
            re.compile(
                r"^[a-z0-9-]+\.icloud\.com$",
                re.IGNORECASE,
            ),
            re.compile(
                r"^mx\d+\.mail\.icloud\.com$",
                re.IGNORECASE,
            ),
        ),
    ),
    MXPattern(
        name=NAMECHEAP_PRIVATE_EMAIL,
        patterns=(
            re.compile(
                r"^(?:mx\d+|mail)\."
                r"(?:privateemail|namecheaphosting)\.com$",
                re.IGNORECASE,
            ),
        ),
    ),
)


def _normalize_hostname(hostname: str) -> str:
    """
    Normalize an MX hostname.

    A DNS null MX is represented as ".". It is deliberately converted
    to an empty string so that it cannot accidentally match a provider
    rule.
    """
    value = hostname.strip().lower()

    if value == ".":
        return ""

    return value.rstrip(".")


def _matches_provider(
    hostname: str,
    provider: MXPattern,
) -> bool:
    """
    Return True when a hostname matches at least one rule for a provider.
    """
    return any(
        pattern.fullmatch(hostname) is not None
        for pattern in provider.patterns
    )


def _detect_from_hosts(
    mx_hosts: list[str] | tuple[str, ...],
) -> frozenset[str]:
    """
    Detect all known providers represented by the supplied MX hosts.
    """
    providers: set[str] = set()

    normalized_hosts: set[str] = set()

    for hostname in mx_hosts:
        if not isinstance(hostname, str):
            continue

        normalized = _normalize_hostname(hostname)

        if normalized:
            normalized_hosts.add(normalized)

    for hostname in normalized_hosts:
        for provider in _MX_RULES:
            if _matches_provider(hostname, provider):
                providers.add(provider.name)

    return frozenset(providers)


def detect_mx_provider(
    mx_hosts: list[str] | tuple[str, ...] | None,
) -> str | None:
    """
    Detect a single known MX provider.

    Returns:
        Provider name when exactly one known provider is detected.

        None when:
            - no known provider is detected
            - multiple different known providers are detected
            - MX hosts are missing/invalid
    """
    if not mx_hosts:
        return None

    providers = _detect_from_hosts(mx_hosts)

    if len(providers) != 1:
        return None

    return next(iter(providers))


def detect_mx_providers(
    mx_hosts: list[str] | tuple[str, ...] | None,
) -> frozenset[str]:
    """
    Detect all known MX providers represented by the supplied hosts.

    This is useful when callers need diagnostic information instead of
    the conservative single-provider result.
    """
    if not mx_hosts:
        return frozenset()

    return _detect_from_hosts(mx_hosts)
