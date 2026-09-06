"""Tests for user-agent parsing."""

from __future__ import annotations

from app.services.user_agent_service import UserAgentService


def _svc() -> UserAgentService:
    return UserAgentService()


def test_chrome() -> None:
    result = _svc().parse(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/41.0.2272.89 Safari/537.36"
    )
    assert result.is_valid is True
    assert result.browser_family == "Chrome"
    assert result.browser_version is not None


def test_firefox() -> None:
    result = _svc().parse(
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0"
    )
    assert result.is_valid is True
    assert result.browser_family == "Firefox"


def test_safari() -> None:
    result = _svc().parse(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.2 Safari/605.1.15"
    )
    assert result.is_valid is True
    assert result.browser_family == "Safari"


def test_mobile() -> None:
    result = _svc().parse(
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
    )
    assert result.device_type == "mobile"


def test_bot() -> None:
    result = _svc().parse(
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    )
    assert result.is_valid is True
    assert result.device_type == "spider"


def test_malformed_empty() -> None:
    result = _svc().parse("")
    assert result.is_valid is False
    assert result.invalid_reason is not None


def test_malformed_too_short() -> None:
    result = _svc().parse("ab")
    assert result.is_valid is False


def test_unknown_but_valid() -> None:
    result = _svc().parse("fnord-ua/1.2.3")
    assert result.is_valid is True


def test_desktop_device_family_is_desktop() -> None:
    result = _svc().parse(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"
    )
    assert result.device_type == "computer"
    assert result.device_family == "Desktop"
    # Hardware manufacturer/model are not transmitted in a normal desktop UA.
    assert result.device_brand is None
    assert result.device_model is None
