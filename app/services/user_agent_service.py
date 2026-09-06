"""User-Agent parsing service built on ``ua-parser``.

Distinguishes 'valid but unknown' from 'malformed'. An empty or whitespace-only
string is malformed; an unknown-but-well-formed UA is valid.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ua_parser import user_agent_parser

_MIN_UA_LENGTH = 4


@dataclass(slots=True)
class UserAgentResult:
    browser_family: str | None
    browser_version: str | None
    os_family: str | None
    os_version: str | None
    device_family: str | None
    device_brand: str | None
    device_model: str | None
    device_type: str | None
    is_valid: bool
    invalid_reason: str | None


def _parse_version(version: dict[str, Any]) -> str | None:
    major = version.get("major")
    minor = version.get("minor")
    patch = version.get("patch")
    parts = [p for p in (major, minor, patch) if p not in (None, "")]
    return ".".join(parts) if parts else None


class UserAgentService:
    def parse(self, useragent: str) -> UserAgentResult:
        raw = useragent.strip()
        if not raw:
            return UserAgentResult(
                browser_family=None,
                browser_version=None,
                os_family=None,
                os_version=None,
                device_family=None,
                device_brand=None,
                device_model=None,
                device_type=None,
                is_valid=False,
                invalid_reason="empty user-agent",
            )
        if len(raw) < _MIN_UA_LENGTH:
            return UserAgentResult(
                browser_family=None,
                browser_version=None,
                os_family=None,
                os_version=None,
                device_family=None,
                device_brand=None,
                device_model=None,
                device_type=None,
                is_valid=False,
                invalid_reason="too short to be a valid user-agent",
            )

        # ua-parser 0.x exposes Parse() -> dict while current releases expose
        # parse() -> typed Result. Keep both paths so upgrades do not break the
        # endpoint.
        parse_legacy = getattr(user_agent_parser, "Parse", None)
        if parse_legacy is not None:
            parsed = parse_legacy(raw)
            ua = parsed.get("user_agent") or {}
            os_info = parsed.get("os") or {}
            device = parsed.get("device") or {}
        else:
            parser_mod: Any = user_agent_parser
            parsed = parser_mod.parse(raw)
            ua_obj = parsed.user_agent
            os_obj = parsed.os
            device_obj = parsed.device
            ua = {
                "family": ua_obj.family,
                "major": ua_obj.major,
                "minor": ua_obj.minor,
                "patch": ua_obj.patch,
            }
            os_info = {
                "family": os_obj.family,
                "major": os_obj.major,
                "minor": os_obj.minor,
                "patch": os_obj.patch,
            }
            device = {
                "family": device_obj.family,
                "brand": device_obj.brand,
                "model": device_obj.model,
            }

        # ua-parser reports unknown entries with a special family value.
        is_unknown = (ua.get("family") or "").lower() == "other" and (
            os_info.get("family") or ""
        ).lower() == "other"

        return UserAgentResult(
            browser_family=_none_if_other(ua.get("family")),
            browser_version=_parse_version(ua),
            os_family=_none_if_other(os_info.get("family")),
            os_version=_parse_version(os_info),
            device_family=_device_family(
                device.get("family"),
                os_family=os_info.get("family"),
            ),
            device_brand=_none_if_other(device.get("brand")),
            device_model=_none_if_other(device.get("model")),
            device_type=_map_device_type(device.get("family"), raw),
            is_valid=True,
            invalid_reason=None if not is_unknown else "valid but unrecognized",
        )


def _none_if_other(value: object | None) -> str | None:
    if value is None:
        return None
    text = str(value)
    if text.lower() in ("other", "generic", ""):
        return None
    return text


def _device_family(family: str | None, *, os_family: str | None) -> str | None:
    """Return a useful device family without inventing hardware details.

    Desktop UAs normally contain no manufacturer/model information. In that
    case "Desktop" is the only defensible family-level answer; brand/model
    remain None because they cannot be inferred from the HTTP User-Agent.
    """
    normalized = _none_if_other(family)
    if normalized:
        return normalized
    if os_family and _none_if_other(os_family):
        return "Desktop"
    return None


def _map_device_type(family: str | None, raw: str) -> str | None:
    family_l = (family or "").lower()
    raw_l = raw.lower()
    if "spider" in family_l or "bot" in family_l or "bot" in raw_l or "crawler" in raw_l:
        return "spider"
    if "phone" in family_l or "mobile" in family_l or "iphone" in family_l:
        return "mobile"
    if "tablet" in family_l or "ipad" in family_l:
        return "tablet"
    if "smart tv" in family_l or "tv" in family_l:
        return "television"
    if family_l or raw_l:
        return "computer"
    return None
