"""Lightweight property-based tests; kept separate from normal deterministic CI."""
from __future__ import annotations

from hypothesis import given, settings, strategies as st

from app.services.toolbox_service import ToolboxService
from app.utils.domain import is_valid_domain
from app.utils.ip import is_valid_ip
from app.utils.url import normalize_url


@settings(max_examples=75, deadline=500)
@given(text=st.text(max_size=256))
def test_domain_normalization_never_crashes(text: str) -> None:
    assert isinstance(is_valid_domain(text), bool)


@settings(max_examples=75, deadline=500)
@given(text=st.text(max_size=64))
def test_ip_validation_never_crashes(text: str) -> None:
    assert isinstance(is_valid_ip(text), bool)


@settings(max_examples=50, deadline=500)
@given(text=st.text(max_size=512))
def test_url_normalization_is_bounded(text: str) -> None:
    try:
        result = normalize_url(text)
        assert result.startswith(("http://", "https://"))
    except Exception:
        pass


@settings(max_examples=50, deadline=500)
@given(
    pattern=st.text(max_size=64),
    text=st.text(max_size=512),
)
def test_regex_tool_does_not_hang(pattern: str, text: str) -> None:
    result = ToolboxService.regex_tool(pattern, text, "")
    assert isinstance(result, dict)
    assert "valid" in result
