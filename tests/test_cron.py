"""Cron generator and parser service tests (fully offline)."""

from __future__ import annotations

import pytest
from app.core.exceptions import ValidationError
from app.services.cron_service import CronService


def test_generate_every_minute() -> None:
    result = CronService.generate("every minute")
    assert result["expression"] == "* * * * *"
    assert result["description"] == "every minute"


def test_generate_every_n_minutes() -> None:
    result = CronService.generate("every 5 minutes")
    assert result["expression"] == "*/5 * * * *"
    assert result["description"] == "every 5 minutes"


def test_generate_every_n_hours() -> None:
    result = CronService.generate("every 6 hours")
    assert result["expression"] == "0 */6 * * *"


def test_generate_daily_at() -> None:
    result = CronService.generate("every day at 09:30")
    assert result["expression"] == "30 9 * * *"
    assert "09:30" in result["description"]


def test_generate_weekday_at() -> None:
    result = CronService.generate("every weekday at 18:00")
    assert result["expression"] == "0 18 * * 1-5"


def test_generate_named_weekday() -> None:
    result = CronService.generate("every monday at 08:15")
    assert result["expression"] == "15 8 * * 1"


def test_generate_specific_date() -> None:
    result = CronService.generate("on january 1, 2027 at 09:00")
    assert result["expression"] == "0 9 1 1 *"


def test_generate_monthly() -> None:
    result = CronService.generate("every month on day 1 at 08:00")
    assert result["expression"] == "0 8 1 * *"


def test_generate_unknown_raises() -> None:
    with pytest.raises(ValidationError):
        CronService.generate("whenever the sun rises")


def test_generated_expression_is_parseable() -> None:
    for schedule in (
        "every minute",
        "every 5 minutes",
        "every 6 hours",
        "every day at 09:30",
        "every weekday at 18:00",
        "every monday at 08:15",
        "every month on day 1 at 08:00",
        "on january 1, 2027 at 09:00",
    ):
        result = CronService.generate(schedule)
        parsed = CronService.parse(result["expression"], count=3)
        assert parsed["valid"] is True


def test_parse_expands_star() -> None:
    result = CronService.parse("* * * * *", count=1)
    assert result["valid"] is True
    assert result["fields"]["minute"]["values"] == list(range(0, 60))


def test_parse_step_values() -> None:
    result = CronService.parse("*/15 * * * *", count=1)
    assert result["fields"]["minute"]["values"] == [0, 15, 30, 45]


def test_parse_list_and_range() -> None:
    result = CronService.parse("30 9 * * 1-5", count=1)
    assert result["fields"]["day_of_week"]["values"] == [1, 2, 3, 4, 5]


def test_parse_weekday_names() -> None:
    result = CronService.parse("0 9 * * mon,fri", count=1)
    assert result["fields"]["day_of_week"]["values"] == [1, 5]


def test_parse_sunday_name_is_zero() -> None:
    result = CronService.parse("0 9 * * SUN", count=1)
    assert result["fields"]["day_of_week"]["values"] == [0]


def test_parse_invalid_field() -> None:
    result = CronService.parse("61 * * * *", count=1)
    assert result["valid"] is False
    assert result["error"]


def test_parse_invalid_step() -> None:
    result = CronService.parse("*/0 * * * *", count=1)
    assert result["valid"] is False


def test_parse_wrong_field_count() -> None:
    result = CronService.parse("0 9 * * * *", count=1)
    assert result["valid"] is False


def test_next_times_are_monotonic_and_utc() -> None:
    result = CronService.parse(
        "0 9 * * *",
        count=5,
        # Friday 2025-09-05 16:00:00Z -> next 09:00 is Sat 09-06.
        reference_timestamp=1757088000,
    )
    assert result["valid"] is True
    times = result["next_times"]
    assert len(times) == 5
    assert all(t.endswith("+00:00") for t in times)
    assert times == sorted(times)
    assert times[0].startswith("2025-09-06T09:00:00")


def test_next_times_steps_respect_minute() -> None:
    result = CronService.parse(
        "*/10 * * * *",
        count=3,
        # Friday 2025-09-05 16:00:00Z.
        reference_timestamp=1757088000,
    )
    times = result["next_times"]
    assert times[0].endswith(":00:00+00:00")
    assert times[1].endswith(":10:00+00:00")


def test_leap_day_only_next() -> None:
    result = CronService.parse(
        "0 0 29 2 *",
        count=1,
        reference_timestamp=1757088000,  # 2025-09-05
    )
    assert result["valid"] is True
    assert result["next_times"][0].startswith("2028-02-29T00:00:00")


def test_weekday_semantics() -> None:
    # Friday 2025-09-05 16:00Z -> next weekday 09:00 is Monday 09-08.
    result = CronService.parse(
        "0 9 * * 1-5",
        count=3,
        reference_timestamp=1757088000,
    )
    times = result["next_times"]
    assert times[0].startswith("2025-09-08T09:00:00")
    assert times[1].startswith("2025-09-09T09:00:00")
