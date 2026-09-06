"""Phone number validation service built on ``phonenumbers``.

Correctly distinguishes 'possible' from 'valid'. Validity here reflects
libphonenumber's numbering-plan rules only - it does NOT assert the number is
currently assigned or reachable.
"""

from __future__ import annotations

from dataclasses import dataclass

import phonenumbers
from phonenumbers import geocoder
from phonenumbers import timezone as pn_timezone


@dataclass(slots=True)
class PhoneResult:
    is_valid: bool
    is_possible: bool
    is_formatted_properly: bool = False
    country: str | None = None
    country_code: int | None = None
    location: str | None = None
    timezones: list[str] | None = None
    format_national: str | None = None
    format_international: str | None = None
    format_e164: str | None = None
    format_rfc3966: str | None = None
    line_type: str | None = None
    is_mobile: bool | None = None
    reason: str | None = None


def _fmt(value: str | None) -> str | None:
    return value if value else None


class PhoneValidationService:
    def validate(self, number: str, country: str | None = None) -> PhoneResult:
        raw = number.strip()
        if not raw:
            return PhoneResult(is_valid=False, is_possible=False, reason="empty number")

        try:
            parsed = phonenumbers.parse(raw, region=country or None)
        except phonenumbers.NumberParseException as exc:
            return PhoneResult(is_valid=False, is_possible=False, reason=str(exc))

        is_possible = phonenumbers.is_possible_number(parsed)
        is_valid = phonenumbers.is_valid_number(parsed)
        if not is_valid:
            reason = "number may be possible but is not valid"
            if not is_possible:
                reason = "number is not a possible number"
            return PhoneResult(
                is_valid=is_valid,
                is_possible=is_possible,
                country_code=int(parsed.country_code) if parsed.country_code else None,
                reason=reason,
            )

        cc = int(parsed.country_code) if parsed.country_code else None
        region = phonenumbers.region_code_for_number(parsed)

        location = None
        if region:
            try:
                loc = geocoder.description_for_number(parsed, "en")
                location = _fmt(loc) or None
            except Exception:
                location = None

        timezones: list[str] = []
        if region:
            try:
                timezones = list(pn_timezone.time_zones_for_number(parsed))
            except Exception:
                timezones = []

        line_type = None
        if region:
            try:
                number_type = phonenumbers.number_type(parsed)
                line_type = phonenumbers.PhoneNumberType.to_string(number_type)
            except Exception:
                line_type = None

        def _country_name(cc: int) -> str | None:
            try:
                name = geocoder.country_name_for_number(parsed, "en")
                if name:
                    return name
            except Exception:
                pass
            codes = phonenumbers.COUNTRY_CODE_TO_REGION_CODE
            if codes.get(cc):
                return codes[cc][0]
            return None

        mobile_types = (
            phonenumbers.PhoneNumberType.MOBILE,
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE,
        )
        is_mobile = phonenumbers.number_type(parsed) in mobile_types if region else None

        return PhoneResult(
            is_valid=True,
            is_possible=True,
            is_formatted_properly=raw.startswith("+"),
            country=_country_name(cc) if cc else None,
            country_code=cc,
            location=location,
            timezones=timezones,
            format_national=phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.NATIONAL
            ),
            format_international=phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
            ),
            format_e164=phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
            format_rfc3966=phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.RFC3966
            ),
            line_type=line_type,
            is_mobile=is_mobile,
        )
