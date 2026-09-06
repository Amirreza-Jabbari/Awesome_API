"""Parked-domain detection (heuristic only).

Presented as intelligence, never as absolute truth. Signals include known
parking name servers. When no signal is found the result is None (unknown),
which is semantically honest.
"""

from __future__ import annotations

import re

_PARKING_NS_PATTERNS = (
    re.compile(r"\.sedoparking\.com\.?$", re.IGNORECASE),
    re.compile(r"\.parklogic\.com\.?$", re.IGNORECASE),
    re.compile(r"parkingcrew\.com\.?$", re.IGNORECASE),
    re.compile(r"above\.com\.?$", re.IGNORECASE),
    re.compile(r"afternic\.com\.?$", re.IGNORECASE),
    re.compile(r"bodis\.com\.?$", re.IGNORECASE),
    re.compile(r"dan\.com\.?$", re.IGNORECASE),
)


def detect_parked_domain(mx_hosts: list[str] | None, ns_hosts: list[str] | None) -> bool | None:
    """Return True/False when confident, otherwise None (unknown)."""
    # A domain with configured MX records is highly unlikely to be parked.
    if mx_hosts:
        return False
    if not ns_hosts:
        return None
    names = [ns.lower().rstrip(".") for ns in ns_hosts]
    for ns in names:
        for pattern in _PARKING_NS_PATTERNS:
            if pattern.search(ns):
                return True
    return None
