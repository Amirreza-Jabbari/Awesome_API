from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

RECORD_TYPES: tuple[str, ...] = (
    "A",
    "AAAA",
    "MX",
    "NS",
    "SOA",
    "TXT",
    "CNAME",
)

_RECORD_TYPE_SET = frozenset(RECORD_TYPES)


def normalize_record_types(
    record_types: tuple[str, ...] | list[str] | None,
) -> tuple[str, ...]:
    """
    Normalize and validate DNS record types.

    - None means all supported record types.
    - whitespace is removed.
    - values are uppercased.
    - duplicates are removed while preserving order.
    - unsupported types raise ValueError.
    """
    if record_types is None:
        return RECORD_TYPES

    normalized: list[str] = []
    seen: set[str] = set()

    for record_type in record_types:
        if not isinstance(record_type, str):
            raise ValueError(
                "DNS record types must be strings."
            )

        value = record_type.strip().upper()

        if not value:
            raise ValueError(
                "DNS record type cannot be empty."
            )

        if value not in _RECORD_TYPE_SET:
            raise ValueError(
                f"Unsupported DNS record type: {value}"
            )

        if value in seen:
            continue

        seen.add(value)
        normalized.append(value)

    if not normalized:
        raise ValueError(
            "At least one DNS record type is required."
        )

    return tuple(normalized)


@dataclass(slots=True)
class DNSRecord:
    """
    Generic normalized DNS record representation.
    """

    record_type: str
    value: str
    priority: int | None = None
    ttl: int | None = None

    mname: str | None = None
    rname: str | None = None
    serial: int | None = None
    refresh: int | None = None
    retry: int | None = None
    expire: int | None = None
    minimum: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize the record using the service/cache representation.
        """
        return {
            "record_type": self.record_type,
            "value": self.value,
            "priority": self.priority,
            "ttl": self.ttl,
            "mname": self.mname,
            "rname": self.rname,
            "serial": self.serial,
            "refresh": self.refresh,
            "retry": self.retry,
            "expire": self.expire,
            "minimum": self.minimum,
        }


@dataclass(frozen=True, slots=True)
class MXData:
    """
    Normalized MX record used by email validation/classification.
    """

    priority: int
    hostname: str


@dataclass(frozen=True, slots=True)
class DNSQuery:
    """
    Provider-neutral DNS lookup request.

    Domain normalization intentionally belongs to the service/application
    layer rather than this provider model.
    """

    domain: str
    record_types: tuple[str, ...] = field(
        default_factory=lambda: RECORD_TYPES
    )

    def __post_init__(self) -> None:
        if not isinstance(self.domain, str):
            raise ValueError(
                "DNS query domain must be a string."
            )

        if not self.domain.strip():
            raise ValueError(
                "DNS query domain cannot be empty."
            )

        normalized_types = normalize_record_types(
            self.record_types
        )

        object.__setattr__(
            self,
            "record_types",
            normalized_types,
        )


@dataclass(slots=True)
class DNSLookupResult:
    """
    Provider-neutral DNS lookup result.
    """

    domain: str
    records: list[DNSRecord]
