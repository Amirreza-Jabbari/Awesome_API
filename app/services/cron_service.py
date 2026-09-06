"""Cron expression generation and parsing.

Generator converts natural-language schedule descriptions into standard
5-field cron expressions. Parser validates expressions and computes the next
N scheduled times - purely locally, without a scheduler daemon.
"""
from __future__ import annotations

import datetime as dt
import re
from typing import Any

from app.core.exceptions import ValidationError

_WEEKDAYS = {
    "sunday": 0, "sun": 0, "monday": 1, "mon": 1, "tuesday": 2, "tue": 2,
    "wednesday": 3, "wed": 3, "thursday": 4, "thu": 4, "friday": 5, "fri": 5,
    "saturday": 6, "sat": 6,
}
_MONTHS = {
    "january": 1, "jan": 1, "february": 2, "feb": 2, "march": 3, "mar": 3,
    "april": 4, "apr": 4, "may": 5, "june": 6, "jun": 6, "july": 7, "jul": 7,
    "august": 8, "aug": 8, "september": 9, "sep": 9, "october": 10, "oct": 10,
    "november": 11, "nov": 11, "december": 12, "dec": 12,
}

_HORIZON_YEARS = 5
_MAX_LOOP_DAYS = _HORIZON_YEARS * 366 + 5


class CronService:
    """Local cron generator and parser."""

    # ------------------------------------------------------------- generator

    @staticmethod
    def generate(schedule: str) -> dict[str, Any]:
        text = (schedule or "").strip().lower()
        expr = CronService._match_schedule(text)
        if expr is None:
            raise ValidationError(
                "Unsupported schedule description. Try e.g. 'every minute', "
                "'every 30 minutes', 'every hour', 'every 6 hours', "
                "'every day at 09:30', 'every monday at 09:30', "
                "'every weekday at 18:00', 'every month on day 1 at 08:00'."
            )
        checks = CronService.parse(expr, count=3)
        if not checks["valid"]:
            raise ValidationError(checks.get("error") or "Invalid generated expression.")
        fields = checks["fields"]
        return {
            "valid": True,
            "error": None,
            "expression": expr,
            "description": CronService._describe([f["value"] for f in fields.values()]),
            "fields": fields,
        }

    @staticmethod
    def _describe(raw_fields: list[str]) -> str:
        minute, hour, dom, month, dow = raw_fields

        def time_of_day(h: str, m: str) -> str:
            if h == "*":
                return f"every hour at minute {m}"
            if h.isdigit() and m.isdigit():
                return f"at {int(h):02d}:{int(m):02d}"
            return f"at {h}:{m}"

        if all(f == "*" for f in raw_fields):
            return "every minute"
        if minute.startswith("*/") and hour == "*" and dom == "*" and month == "*" and dow == "*":
            return f"every {minute[2:]} minutes"
        if hour.startswith("*/") and minute == "0" and dom == "*" and month == "*" and dow == "*":
            return f"every {hour[2:]} hours"
        if dom == "*" and month == "*":
            if dow == "*":
                return f"{time_of_day(hour, minute)} every day"
            if dow == "1-5":
                return f"{time_of_day(hour, minute)} on weekdays"
            if dow == "0,6":
                return f"{time_of_day(hour, minute)} on weekends"
            if dow.isdigit():
                name = next((n for n, v in _WEEKDAYS.items() if v == int(dow) and len(n) > 3), dow)
                return f"{time_of_day(hour, minute)} every {name}"
            return f"{time_of_day(hour, minute)} each of the selected weekdays (cron: {dow})"
        if month == "*" and dom.isdigit():
            return f"{time_of_day(hour, minute)} on day {dom} of every month"
        return f"custom schedule (minute={minute} hour={hour} dom={dom} month={month} dow={dow})"

    @staticmethod
    def _match_schedule(text: str) -> str | None:
        patterns: list[tuple[re.Pattern[str], str]] = [
            (re.compile(r"^every minute$"), "* * * * *"),
            (re.compile(r"^every morning$"), "0 6 * * *"),
            (re.compile(r"^every evening$"), "0 18 * * *"),
        ]
        for pattern, expr in patterns:
            if pattern.match(text):
                return expr
        m = re.match(r"^every (\d{1,2}) minutes?$", text)
        if m:
            n = int(m.group(1))
            if 1 <= n <= 59:
                return f"*/{n} * * * *"
            return None
        m = re.match(r"^every (\d{1,2}) hours?$", text)
        if m:
            n = int(m.group(1))
            if 1 <= n <= 23:
                return f"0 */{n} * * *"
            return None
        m = re.match(
            r"^(?:every day at |every day |daily at |daily |at )?(\d{1,2}):(\d{2})(?: every day)?$",
            text,
        )
        if m:
            hour, minute = int(m.group(1)), int(m.group(2))
            if 0 <= hour <= 23 and 0 <= minute <= 59:
                return f"{minute} {hour} * * *"
            return None
        m = re.match(r"^every (weekday|weekend)s? at (\d{1,2}):(\d{2})$", text)
        if m:
            hour, minute = int(m.group(2)), int(m.group(3))
            if not (0 <= hour <= 23 and 0 <= minute <= 59):
                return None
            dow = "1-5" if m.group(1) == "weekday" else "0,6"
            return f"{minute} {hour} * * {dow}"
        m = re.match(r"^every ([a-z]+) at (\d{1,2}):(\d{2})$", text)
        if m and m.group(1) in _WEEKDAYS:
            hour, minute = int(m.group(2)), int(m.group(3))
            if 0 <= hour <= 23 and 0 <= minute <= 59:
                return f"{minute} {hour} * * {_WEEKDAYS[m.group(1)]}"
            return None
        m = re.match(r"^every month on day (\d{1,2}) at (\d{1,2}):(\d{2})$", text)
        if m:
            day, hour, minute = int(m.group(1)), int(m.group(2)), int(m.group(3))
            if 1 <= day <= 31 and 0 <= hour <= 23 and 0 <= minute <= 59:
                return f"{minute} {hour} {day} * *"
            return None
        m = re.match(r"^on ([a-z]+) (\d{1,2})(?:st|nd|rd|th)?, (\d{4}) at (\d{1,2}):(\d{2})$",
                     text)
        if m and m.group(1) in _MONTHS:
            month, day, _year = _MONTHS[m.group(1)], int(m.group(2)), int(m.group(3))
            hour, minute = int(m.group(4)), int(m.group(5))
            if not (1 <= month <= 12 and 1 <= day <= 31 and 0 <= hour <= 23
                    and 0 <= minute <= 59):
                return None
            return f"{minute} {hour} {day} {month} *"
        return None

    # ---------------------------------------------------------------- parser

    @staticmethod
    def parse(
        expression: str,
        count: int = 10,
        reference_timestamp: float | None = None,
    ) -> dict[str, Any]:
        fields_raw = (expression or "").strip().split()
        field_names = ["minute", "hour", "day_of_month", "month", "day_of_week"]
        if len(fields_raw) != 5:
            return {
                "valid": False,
                "error": "Expected exactly 5 fields (minute hour day month weekday).",
                "fields": None, "next_count": 0, "next_times": [],
            }
        ranges = {
            "minute": (0, 59), "hour": (0, 23), "day_of_month": (1, 31),
            "month": (1, 12), "day_of_week": (0, 6),
        }
        parsed_fields: dict[str, dict[str, Any]] = {}
        overall_valid = True
        flattened: dict[str, set[int]] = {}
        for name, raw in zip(field_names, fields_raw, strict=False):
            lo, hi = ranges[name]
            values, err = CronService._expand_field(raw, lo, hi, name == "day_of_week")
            detail = {
                "value": raw, "values": sorted(values), "valid": err is None, "error": err,
            }
            parsed_fields[name] = detail
            if err is not None:
                overall_valid = False
            else:
                flattened[name] = set(values)
        if not overall_valid:
            return {
                "valid": False,
                "error": "One or more cron fields are invalid.",
                "fields": parsed_fields, "next_count": 0, "next_times": [],
            }
        try:
            reference = (
                dt.datetime.fromtimestamp(reference_timestamp, dt.UTC)
                if reference_timestamp is not None
                else dt.datetime.now(dt.UTC)
            )
        except (OverflowError, OSError, ValueError):
            return {
                "valid": False, "error": "Invalid reference timestamp.",
                "fields": parsed_fields, "next_count": 0, "next_times": [],
            }
        next_times = CronService._next_times(flattened, reference, count)
        if not next_times:
            return {
                "valid": True,
                "error": f"No matching times within {_HORIZON_YEARS} years.",
                "fields": parsed_fields, "next_count": 0, "next_times": [],
            }
        return {
            "valid": True, "error": None, "fields": parsed_fields,
            "next_count": len(next_times), "next_times": next_times,
        }

    @staticmethod
    def _expand_field(
        raw: str, lo: int, hi: int, is_dow: bool
    ) -> tuple[list[int], str | None]:
        def to_int(part: str) -> int:
            if is_dow and part.lower() in _WEEKDAYS:
                return _WEEKDAYS[part.lower()]
            if part.isdigit():
                return int(part)
            raise ValueError("not a number")

        result: set[int] = set()
        try:
            for item in raw.split(","):
                item = item.strip()
                if not item:
                    continue
                if "/" in item:
                    base, step_str = item.split("/", 1)
                    step = int(step_str)
                    if step <= 0:
                        raise ValueError("step must be positive")
                    if base == "*":
                        start, end = lo, hi
                    elif "-" in base:
                        a, b = base.split("-", 1)
                        start, end = to_int(a), to_int(b)
                    else:
                        start = end = to_int(base)
                    if start < lo or end > hi:
                        raise ValueError("range out of bounds")
                    if start > end:
                        raise ValueError("range start > end")
                    for value in range(start, end + 1, step):
                        result.add(value)
                elif item == "*":
                    for value in range(lo, hi + 1):
                        result.add(value)
                elif "-" in item:
                    a, b = item.split("-", 1)
                    start, end = to_int(a), to_int(b)
                    if start < lo or end > hi or start > end:
                        raise ValueError("invalid range")
                    for value in range(start, end + 1):
                        result.add(value)
                else:
                    value = to_int(item)
                    if not (lo <= value <= hi):
                        raise ValueError("value out of bounds")
                    result.add(value)
        except (ValueError, IndexError) as exc:
            return [], str(exc)
        values = [v for v in result if lo <= v <= hi]
        return values, None

    @staticmethod
    def _days_match(
        dom: set[int], month: set[int], dow: set[int],
        dom_restricted: bool, dow_restricted: bool,
        day: int, weekday: int, mon: int,
    ) -> bool:
        if mon not in month:
            return False
        dom_match = day in dom
        dow_match = weekday in dow
        if dom_restricted and dow_restricted:
            return dom_match or dow_match
        return dom_match and dow_match

    @staticmethod
    def _next_times(
        fields: dict[str, set[int]], reference: dt.datetime, count: int
    ) -> list[str]:
        minutes = fields["minute"]
        hours = fields["hour"]
        dom = fields["day_of_month"]
        months = fields["month"]
        dow = fields["day_of_week"]
        dom_restricted = dom != set(range(1, 32))
        dow_restricted = dow != set(range(0, 7))
        # Express the reference at minute granularity.
        ref_floor = reference.replace(second=0, microsecond=0)
        current_date = ref_floor.date()
        upcoming: list[str] = []
        loop_days = 0
        while loop_days <= _MAX_LOOP_DAYS and len(upcoming) < count:
            weekday = (current_date.weekday() + 1) % 7  # 0 == Sunday
            if CronService._days_match(
                dom, months, dow, dom_restricted, dow_restricted,
                current_date.day, weekday, current_date.month,
            ):
                for hour in sorted(hours):
                    for minute in sorted(minutes):
                        candidate = dt.datetime(
                            current_date.year, current_date.month, current_date.day,
                            hour, minute, tzinfo=_dt_utc(),
                        )
                        if candidate < ref_floor:
                            continue
                        if len(upcoming) >= count:
                            break
                        upcoming.append(candidate.isoformat())
            current_date += dt.timedelta(days=1)
            loop_days += 1
        return upcoming


def _dt_utc() -> dt.timezone:
    return dt.UTC
