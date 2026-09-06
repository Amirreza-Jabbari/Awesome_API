"""Domain parsing, normalization and validation helpers.

Handles:

* ASCII domains
* IDN / Unicode domains
* trailing root dots
* hostname extraction from URLs
* TLD extraction
* conservative registrable-domain detection

The registrable-domain implementation intentionally uses a small built-in
suffix set. It is a heuristic and must not be treated as an authoritative
Public Suffix List implementation.
"""

from __future__ import annotations

import re
from functools import lru_cache
from urllib.parse import urlparse

import idna

from app.core.exceptions import InvalidDomainError
from app.utils.ip import parse_ip

_MAX_DOMAIN_LENGTH = 253
_MAX_LABEL_LENGTH = 63

_DOMAIN_LABEL_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)

_PUBLIC_SUFFIXES = frozenset(
    {
        "co.uk",
        "org.uk",
        "me.uk",
        "ac.uk",
        "gov.uk",
        "net.uk",
        "ltd.uk",
        "plc.uk",
        "com.au",
        "net.au",
        "org.au",
        "edu.au",
        "gov.au",
        "asn.au",
        "id.au",
        "co.jp",
        "or.jp",
        "ne.jp",
        "ac.jp",
        "go.jp",
        "ad.jp",
        "ed.jp",
        "gr.jp",
        "co.nz",
        "net.nz",
        "org.nz",
        "govt.nz",
        "ac.nz",
        "com.br",
        "net.br",
        "org.br",
        "gov.br",
        "edu.br",
        "art.br",
        "blog.br",
        "co.in",
        "net.in",
        "org.in",
        "gov.in",
        "edu.in",
        "firm.in",
        "com.cn",
        "net.cn",
        "org.cn",
        "gov.cn",
        "edu.cn",
        "com.mx",
        "net.mx",
        "org.mx",
        "edu.mx",
        "gob.mx",
        "co.za",
        "org.za",
        "gov.za",
        "net.za",
        "com.sg",
        "net.sg",
        "org.sg",
        "gov.sg",
        "edu.sg",
        "com.hk",
        "net.hk",
        "org.hk",
        "gov.hk",
        "edu.hk",
    }
)

_SINGLE_LABEL_CCTLDS = frozenset(
    {
        "ai",
        "io",
        "tv",
        "me",
        "cc",
        "co",
        "sh",
        "ac",
        "fm",
        "dj",
        "gg",
        "je",
        "im",
        "vg",
        "ws",
        "ly",
        "to",
    }
)


def strip_trailing_dot(domain: str) -> str:
    """Remove one DNS root-label dot from a domain.

    A valid fully-qualified DNS name may end with ``.``. For application-level
    hostname normalization we represent the same name without that root dot.
    """
    if not isinstance(domain, str):
        raise InvalidDomainError("domain must be a string")

    return domain[:-1] if domain.endswith(".") else domain


def _validate_ascii_domain(ascii_domain: str) -> None:
    """Validate a normalized ASCII/punycode domain label-by-label."""
    if not ascii_domain:
        raise InvalidDomainError("empty domain")

    if len(ascii_domain) > _MAX_DOMAIN_LENGTH:
        raise InvalidDomainError("domain exceeds maximum length")

    labels = ascii_domain.split(".")

    if len(labels) < 2:
        raise InvalidDomainError("domain must contain a TLD")

    for label in labels:
        if not label:
            raise InvalidDomainError("domain contains an empty label")

        if len(label) > _MAX_LABEL_LENGTH:
            raise InvalidDomainError(
                "domain label exceeds maximum length"
            )

        if not _DOMAIN_LABEL_RE.fullmatch(label):
            raise InvalidDomainError(
                "invalid domain characters"
            )


def to_ascii(domain: str) -> str:
    """Convert a domain to canonical ASCII/punycode form.

    Raises ``InvalidDomainError`` for malformed domain names.
    """
    if not isinstance(domain, str):
        raise InvalidDomainError("domain must be a string")

    candidate = strip_trailing_dot(domain.strip().lower())

    if not candidate:
        raise InvalidDomainError("empty domain")

    # Reject embedded whitespace before IDNA processing. This produces a much
    # clearer application-level validation result than relying on downstream
    # IDNA behavior.
    if any(character.isspace() for character in candidate):
        raise InvalidDomainError("domain contains whitespace")

    try:
        ascii_domain = idna.encode(
            candidate,
            uts46=True,
        ).decode("ascii").lower()

    except (idna.IDNAError, UnicodeError) as exc:
        raise InvalidDomainError(
            f"invalid IDN: {exc}"
        ) from exc

    _validate_ascii_domain(ascii_domain)

    return ascii_domain


def normalize_domain(domain: str) -> str:
    """Normalize a user-supplied domain into canonical ASCII form."""
    return to_ascii(domain)


def is_valid_domain(domain: str) -> bool:
    """Return ``True`` when the value is a valid normalized domain."""
    try:
        to_ascii(domain)
        return True
    except InvalidDomainError:
        return False


@lru_cache(maxsize=4096)
def get_tld(domain: str) -> str | None:
    """Return the final label/TLD of a normalized domain.

    ``domain`` is normalized defensively so callers are not required to know
    whether the helper is being called with a Unicode or ASCII value.
    """
    ascii_domain = to_ascii(domain)
    labels = strip_trailing_dot(ascii_domain).split(".")

    if len(labels) < 2:
        return None

    return labels[-1]


@lru_cache(maxsize=4096)
def get_registrable_domain(domain: str) -> str | None:
    """Return a conservative heuristic for the registrable domain.

    This is NOT a full Public Suffix List implementation.

    Examples:

    * ``mail.example.com`` -> ``example.com``
    * ``mail.example.co.uk`` -> ``example.co.uk``
    * ``foo.example.ai`` -> ``example.ai``

    Unknown suffix structures fall back to the final two labels.
    """
    ascii_domain = to_ascii(domain)

    labels = strip_trailing_dot(ascii_domain).split(".")

    if len(labels) < 2:
        return None

    last_two = ".".join(labels[-2:]).lower()

    if last_two in _PUBLIC_SUFFIXES:
        if len(labels) < 3:
            return ascii_domain

        return ".".join(labels[-3:])

    tld = labels[-1].lower()

    if tld in _SINGLE_LABEL_CCTLDS:
        return ".".join(labels[-2:])

    return ".".join(labels[-2:])


def extract_domain_from_url(url: str) -> str:
    """Extract and normalize the hostname from a URL.

    Both normal URLs and schemeless host/path inputs are accepted.

    URL scheme validation intentionally remains outside this helper.
    """
    if not isinstance(url, str):
        raise InvalidDomainError("URL must be a string")

    candidate = url.strip()

    if not candidate:
        raise InvalidDomainError("empty URL")

    if "://" not in candidate:
        candidate = "//" + candidate

    try:
        parsed = urlparse(candidate)
        host = parsed.hostname

    except ValueError as exc:
        raise InvalidDomainError(
            "invalid URL hostname"
        ) from exc

    if not host:
        raise InvalidDomainError("no hostname in URL")

    # IPv4/IPv6 literals are valid URL hosts and do not have a DNS TLD.
    try:
        return str(parse_ip(host))
    except ValueError:
        return normalize_domain(host)


def is_risky_tld(
    tld: str,
    risky_set: frozenset[str],
) -> bool:
    """Return ``True`` when the TLD is in the configured risky set."""
    if not isinstance(tld, str):
        return False

    return tld.strip().lower().lstrip(".") in risky_set
