"""Developer-tool service tests: SQL, SemVer, changelog, color (offline)."""

from __future__ import annotations

import pytest
from app.core.exceptions import ValidationError
from app.services.dev_tools_service import DevToolsService


def test_sql_format_upper_keywords() -> None:
    result = DevToolsService.sql_format(
        "select * from users where id = 1", "upper", 2, False, True,
    )
    assert result["valid"] is True
    assert "SELECT" in result["formatted"]


def test_sql_format_stmt_count() -> None:
    result = DevToolsService.sql_format("SELECT 1; SELECT 2;", "upper", 2, False, True)
    assert result["statement_count"] == 2


def test_sql_format_unbalanced_issue() -> None:
    result = DevToolsService.sql_format("SELECT (1", "upper", 2, False, True)
    assert result["valid"] is False
    assert any("parentheses" in i for i in result["issues"])


def test_sql_minify_strips_comments() -> None:
    result = DevToolsService.sql_minify("SELECT 1 -- c", "upper", True)
    assert result["valid"] is True
    assert result["removed_comments"] == 1
    assert "-- c" not in result["minified"]


def test_sql_minify_keeps_comments_when_disabled() -> None:
    result = DevToolsService.sql_minify("SELECT 1 -- c", "upper", False)
    assert result["removed_comments"] == 0


def test_sql_validate_ok() -> None:
    result = DevToolsService.sql_validate("SELECT * FROM t WHERE x = (1 + 2);")
    assert result["valid"] is True


def test_sql_validate_unbalanced_parens() -> None:
    result = DevToolsService.sql_validate("SELECT (1")
    assert result["valid"] is False


def test_sql_validate_empty() -> None:
    result = DevToolsService.sql_validate("   ")
    assert result["valid"] is False


def test_semver_parse_components() -> None:
    result = DevToolsService.semver("1.2.3-beta.1+build.5", None, None)
    assert result["valid"] is True
    assert result["major"] == 1
    assert result["minor"] == 2
    assert result["patch"] == 3
    assert result["prerelease"] == "beta.1"
    assert result["build"] == "build.5"
    assert result["is_prerelease"] is True


def test_semver_invalid() -> None:
    result = DevToolsService.semver("not.a.version", None, None)
    assert result["valid"] is False
    assert result["error"]


def test_semver_comparison_detects_breaking() -> None:
    result = DevToolsService.semver("2.0.0", "1.9.9", None)
    assert result["comparison"]["comparable"] is True
    assert result["comparison"]["is_breaking"] is True


def test_semver_breaking_is_minor_for_zero_major() -> None:
    result = DevToolsService.semver("0.2.0", "0.1.9", None)
    assert result["comparison"]["is_breaking"] is True


def test_semver_range_caret() -> None:
    assert DevToolsService.semver("1.4.5", None, "^1.0.0")["range_result"]["matches"] is True
    assert DevToolsService.semver("2.0.0", None, "^1.0.0")["range_result"]["matches"] is False


def test_semver_range_tilde_and_or() -> None:
    assert DevToolsService.semver("1.2.9", None, "~1.2.0")["range_result"]["matches"] is True
    assert DevToolsService.semver("1.3.0", None, "~1.2.0")["range_result"]["matches"] is False
    assert DevToolsService.semver("0.5.0", None, "<0.1.0 || >=0.5.0")["range_result"]["matches"] is True  # noqa: E501


def test_changelog_sections() -> None:
    commits = [
        {"type": "feat", "description": "add widgets"},
        {"type": "fix", "description": "repair gadget"},
        {"type": "perf", "description": "speed things up"},
    ]
    result = DevToolsService.changelog(commits, "1.0.0", "2026-09-05", None, False)
    assert any("widgets" in line for line in result["sections"]["feat"])
    assert any("repair gadget" in line for line in result["sections"]["fix"])
    assert any("speed things up" in line for line in result["sections"]["perf"])
    assert result["markdown"].startswith("## 1.0.0 (2026-09-05)")


def test_changelog_breaking_separated() -> None:
    commits = [
        {"type": "feat", "description": "old api", "breaking": True},
        {"type": "feat", "description": "new api"},
    ]
    result = DevToolsService.changelog(commits, None, None, "Unreleased", True)
    assert result["sections"]["feat"] == ["- feat: new api"]
    assert all("old api" not in line for line in result["sections"]["feat"])
    assert "Breaking Changes" in result["markdown"]
    assert "old api" in result["markdown"]


def test_changelog_deprecations_and_removals() -> None:
    commits = [
        {"type": "other", "description": "deprecate old flag"},
        {"type": "other", "description": "drop legacy mode"},
    ]
    result = DevToolsService.changelog(commits, "2.0.0", "2026-09-05", None, False)
    assert any("deprecate old flag" in line for line in result["sections"]["other"])


def test_changelog_title_version() -> None:
    commits = [{"type": "fix", "description": "tweak"}]
    result = DevToolsService.changelog(commits, "3.1.0", "2026-01-02", "My Release", False)
    assert result["markdown"].startswith("# My Release\n")
    assert result["markdown"].count("## 3.1.0 (2026-01-02)") == 1


def test_color_convert_named_color() -> None:
    result = DevToolsService().color_convert("red", "name", None)
    assert result["valid"] is True
    assert result["hex"] == "#ff0000"
    assert result["css"]["rgb"] == "rgb(255, 0, 0)"


def test_color_convert_hsl_to_hex() -> None:
    result = DevToolsService().color_convert("hsl(0, 100%, 50%)", "hsl", None)
    assert result["valid"] is True
    assert result["hex"] == "#ff0000"


def test_color_convert_contrast() -> None:
    result = DevToolsService().color_convert("#ff0000", "hex", "#ffffff")
    assert result["valid"] is True
    assert result["contrast"] is not None
    assert result["contrast"] > 1.0


def test_color_convert_unknown() -> None:
    with pytest.raises(ValidationError):
        DevToolsService().color_convert("not-a-color", "auto", None)


def test_color_convert_rgba_alpha() -> None:
    result = DevToolsService().color_convert("rgba(255, 0, 0, 0.5)", "rgba", None)
    assert result["valid"] is True
    assert result["rgba"]["a"] == 0.5
