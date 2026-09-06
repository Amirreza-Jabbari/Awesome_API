"""Developer utilities: SQL tools, SemVer, changelog and color conversion.

All SQL operations are static / syntax-only - submitted SQL is **never**
executed or sent to a database server. SemVer parsing follows the 2.0.0
spec with built-in range support. Color conversion is pure arithmetic with no
external service calls.
"""
from __future__ import annotations

import re
from typing import Any

import sqlparse


def _count_statements(sql: str) -> int:
    return len([s for s in sql.split(";") if s.strip()])


class DevToolsService:
    """Pure developer-utility service (SQL, SemVer, changelog, color)."""

    # ------------------------------------------------------------------ SQL

    @staticmethod
    def sql_format(
        sql: str,
        keyword_case: str,
        indent: int,
        strip_comments: bool,
        reindent: bool,
    ) -> dict[str, Any]:
        try:
            formatted = sqlparse.format(
                sql, reindent=reindent, keyword_case=keyword_case,
                strip_comments=strip_comments, indent=indent,
            )
        except Exception as exc:
            return {
                "valid": False, "formatted": None, "statement_count": 0,
                "issues": [], "error": str(exc),
            }
        issues: list[str] = []
        open_p = sql.count("(")
        close_p = sql.count(")")
        if open_p != close_p:
            issues.append(
                f"Mismatched parentheses (found {open_p} open, {close_p} close)."
            )
        if sql.count("'") % 2 != 0:
            issues.append("Mismatched single quotes.")
        return {
            "valid": not issues, "formatted": formatted,
            "statement_count": _count_statements(formatted), "issues": issues,
            "error": None,
        }

    @staticmethod
    def sql_minify(sql: str, keyword_case: str, strip_comments: bool) -> dict[str, Any]:
        try:
            comments = 0
            if strip_comments:
                for stmt in sqlparse.parse(sql):
                    for token in stmt.flatten():  # type: ignore[no-untyped-call]
                        if token.ttype in (sqlparse.tokens.Comment,
                                           sqlparse.tokens.Comment.Single,
                                           sqlparse.tokens.Comment.Multiline):
                            comments += 1
            minified = sqlparse.format(
                sql, strip_comments=strip_comments, keyword_case=keyword_case,
                compact=True,
            )
        except Exception as exc:
            return {
                "valid": False, "minified": None, "removed_comments": 0,
                "statement_count": 0, "original_length": 0,
                "minified_length": 0, "error": str(exc),
            }
        return {
            "valid": True, "minified": minified, "removed_comments": comments,
            "statement_count": _count_statements(minified),
            "original_length": len(sql), "minified_length": len(minified),
            "error": None,
        }

    @staticmethod
    def sql_validate(sql: str) -> dict[str, Any]:
        try:
            statements = sqlparse.parse(sql)
        except Exception as exc:
            return {
                "valid": False, "statement_count": 0,
                "errors": [str(exc)], "warnings": [],
            }
        if not statements or all(not s.tokens for s in statements):
            return {
                "valid": False, "statement_count": 0,
                "errors": ["Empty SQL input."], "warnings": [],
            }
        errors: list[str] = []
        warnings: list[str] = []
        for idx, stmt in enumerate(statements):
            flat = [t for t in stmt.flatten()]  # type: ignore[no-untyped-call]
            if not any(t.ttype is not sqlparse.tokens.Whitespace
                       and t.ttype not in (sqlparse.tokens.Comment,
                                           sqlparse.tokens.Comment.Single,
                                           sqlparse.tokens.Comment.Multiline)
                       for t in flat):
                continue
            text = stmt.value
            if text.count("(") != text.count(")"):
                errors.append(f"Statement {idx + 1}: unbalanced parentheses.")
        return {"valid": not errors, "statement_count": len(statements),
                "errors": errors, "warnings": warnings}

    # --------------------------------------------------------------- SemVer

    @staticmethod
    def semver(
        version: str,
        other: str | None,
        range_str: str | None,
    ) -> dict[str, Any]:
        parsed = DevToolsService._parse_semver(version)
        if parsed is None:
            return {
                "valid": False,
                "error": "Invalid semantic version (expected MAJOR.MINOR.PATCH "
                         "with optional -prerelease and +build).",
                "major": None, "minor": None, "patch": None,
                "prerelease": None, "build": None, "core": None,
                "is_prerelease": False, "comparison": None, "range_result": None,
            }
        out: dict[str, Any] = {
            "valid": True, "error": None,
            "major": parsed["major"], "minor": parsed["minor"], "patch": parsed["patch"],
            "prerelease": parsed["prerelease"], "build": parsed["build"],
            "core": parsed["core"], "is_prerelease": parsed["prerelease"] is not None,
            "comparison": None, "range_result": None,
        }
        if other:
            other_parsed = DevToolsService._parse_semver(other)
            if other_parsed is None:
                result = {
                    "comparable": False, "other": other, "value": None,
                    "is_breaking": None,
                    "reason": "other version is not a valid SemVer string.",
                }
            else:
                cmp_val = DevToolsService._semver_compare(parsed, other_parsed)
                result = {
                    "comparable": True, "other": other, "value": cmp_val,
                    "is_breaking": (
                        parsed["major"] != other_parsed["major"]
                        if parsed["major"] > 0 or other_parsed["major"] > 0
                        else parsed["minor"] != other_parsed["minor"]
                    ),
                    "reason": None,
                }
            out["comparison"] = result
        if range_str:
            out["range_result"] = DevToolsService._satisfies(parsed, range_str)
        return out

    @staticmethod
    def _parse_semver(text: str) -> dict[str, Any] | None:
        regex = re.compile(
            r"^(?:v|V)?(?P<major>0|[1-9]\d*)"
            r"\.(?P<minor>0|[1-9]\d*)"
            r"\.(?P<patch>0|[1-9]\d*)"
            r"(?:-(?P<prerelease>"
            r"(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
            r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*"
            r"))?"
            r"(?:\+(?P<build>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
        )
        m = regex.match(text.strip())
        if not m:
            return None
        prerelease = m.group("prerelease") or None
        if prerelease:
            for part in prerelease.split("."):
                if not part:
                    return None
                if part.startswith("0") and len(part) > 1 and part.isdigit():
                    return None
        return {
            "major": int(m.group("major")),
            "minor": int(m.group("minor")),
            "patch": int(m.group("patch")),
            "prerelease": prerelease,
            "build": m.group("build") or None,
            "core": "{}.{}.{}".format(
                m.group("major"), m.group("minor"), m.group("patch"),
            ),
        }

    @staticmethod
    def _semver_parts(prerelease: str | None) -> list[tuple[int, str]]:
        parts: list[tuple[int, str]] = []
        if not prerelease:
            return parts
        for part in prerelease.split("."):
            parts.append((0, part) if part.isdigit() else (1, part))
        return parts

    @staticmethod
    def _semver_compare(a: dict[str, Any], b: dict[str, Any]) -> int:
        acore = (a["major"], a["minor"], a["patch"])
        bcore = (b["major"], b["minor"], b["patch"])
        if acore != bcore:
            return -1 if acore < bcore else 1
        apre = a["prerelease"]
        bpre = b["prerelease"]
        if apre and not bpre:
            return 1
        if not apre and bpre:
            return -1
        if not apre and not bpre:
            return 0
        alist = DevToolsService._semver_parts(apre)
        blist = DevToolsService._semver_parts(bpre)
        for i in range(max(len(alist), len(blist))):
            if i >= len(alist):
                return -1
            if i >= len(blist):
                return 1
            atype, aval = alist[i]
            btype, bval = blist[i]
            if atype != btype:
                return 1 if atype > btype else -1
            if atype == 0:
                av, bv = int(aval), int(bval)
                if av != bv:
                    return -1 if av < bv else 1
            else:
                if aval != bval:
                    return -1 if aval < bval else 1
        return 0

    @staticmethod
    def _satisfies(version: dict[str, Any], range_str: str) -> dict[str, Any]:
        alternatives = [a.strip() for a in range_str.split("||") if a.strip()]
        if not alternatives:
            return {"valid": True, "matches": True, "error": None}
        for alt in alternatives:
            comparators = alt.split()
            if not comparators:
                continue
            ok = True
            for comp in comparators:
                op = ""
                ver = comp
                if comp.startswith(">="):
                    op, ver = ">=", comp[2:]
                elif comp.startswith("<="):
                    op, ver = "<=", comp[2:]
                elif comp.startswith("!="):
                    op, ver = "!=", comp[2:]
                elif comp.startswith("^"):
                    op, ver = "^", comp[1:]
                elif comp.startswith("~"):
                    op, ver = "~", comp[1:]
                elif comp.startswith(">"):
                    op, ver = ">", comp[1:]
                elif comp.startswith("<"):
                    op, ver = "<", comp[1:]
                elif comp.startswith("="):
                    op, ver = "=", comp[1:]
                if ver in ("*", "x", "X"):
                    continue
                lower = DevToolsService._parse_semver(ver)
                if lower is None:
                    return {"valid": False, "matches": None,
                            "error": f"Invalid version in range: {comp!r}"}
                cmp_res = DevToolsService._semver_compare(version, lower)
                if op in ("", "="):
                    matched = cmp_res == 0
                elif op == ">":
                    matched = cmp_res > 0
                elif op == ">=":
                    matched = cmp_res >= 0
                elif op == "<":
                    matched = cmp_res < 0
                elif op == "<=":
                    matched = cmp_res <= 0
                elif op == "!=":
                    matched = cmp_res != 0
                elif op == "^":
                    matched = DevToolsService._satisfies_caret(version, lower)
                elif op == "~":
                    matched = DevToolsService._satisfies_tilde(version, lower)
                else:
                    matched = False
                if not matched:
                    ok = False
                    break
            if ok:
                return {"valid": True, "matches": True, "error": None}
        return {"valid": True, "matches": False, "error": None}

    @staticmethod
    def _satisfies_caret(version: dict[str, Any], lower: dict[str, Any]) -> bool:
        upper = dict(lower)
        upper["build"] = None
        upper["prerelease"] = None
        if lower["major"] != 0:
            upper["major"] += 1
            upper["minor"] = 0
            upper["patch"] = 0
        elif lower["minor"] != 0:
            upper["minor"] += 1
            upper["patch"] = 0
        else:
            upper["patch"] += 1
        return (
            DevToolsService._semver_compare(version, lower) >= 0
            and DevToolsService._semver_compare(version, upper) < 0
        )

    @staticmethod
    def _satisfies_tilde(version: dict[str, Any], lower: dict[str, Any]) -> bool:
        upper = dict(lower)
        upper["build"] = None
        upper["prerelease"] = None
        upper["minor"] += 1
        upper["patch"] = 0
        return (
            DevToolsService._semver_compare(version, lower) >= 0
            and DevToolsService._semver_compare(version, upper) < 0
        )

    # ------------------------------------------------------------ Changelog

    @staticmethod
    def changelog(
        commits: list[dict[str, Any]],
        version: str | None,
        date: str | None,
        title: str | None,
        unreleased: bool,
    ) -> dict[str, Any]:
        section_order = ["feat", "fix", "docs", "style", "refactor", "perf",
                         "test", "build", "ci", "chore", "other"]
        section_names = {
            "feat": "Features", "fix": "Bug Fixes", "docs": "Documentation",
            "style": "Styles", "refactor": "Code Refactoring", "perf": "Performance",
            "test": "Tests", "build": "Build System", "ci": "Continuous Integration",
            "chore": "Chores", "other": "Other",
        }
        sections: dict[str, list[str]] = {name: [] for name in section_order}
        counts: dict[str, int] = {name: 0 for name in section_order}
        breaking_lines: list[str] = []
        excluded = 0
        for commit in commits:
            ctype = commit.get("type") or "other"
            desc = (commit.get("description") or "").strip()
            if not desc:
                excluded += 1
                continue
            if ctype not in section_order:
                ctype = "other"
            scope = commit.get("scope")
            prefix = f"{ctype}({scope}): " if scope else f"{ctype}: "
            line = f"- {prefix}{desc}"
            if commit.get("breaking"):
                breaking_lines.append(line)
            else:
                sections[ctype].append(line)
            counts[ctype] += 1

        md_lines: list[str] = []
        if title:
            md_lines.append(f"# {title}\n")
        heading = version or "Unreleased"
        if date:
            heading += f" ({date})"
        md_lines.append(f"## {heading}")
        if unreleased:
            md_lines.append("")
            md_lines.append("> Unreleased changes not yet versioned.\n")
        any_content = False
        for ctype in section_order:
            if sections[ctype]:
                any_content = True
                md_lines.append("")
                md_lines.append(f"### {section_names[ctype]}")
                md_lines.extend(sections[ctype])
        if breaking_lines:
            any_content = True
            md_lines.append("")
            md_lines.append("### Breaking Changes")
            md_lines.extend(breaking_lines)
        if not any_content:
            md_lines.append("")
            md_lines.append("_No notable changes._")
        return {
            "markdown": "\n".join(md_lines).strip() + "\n",
            "sections": {name: sections[name] for name in section_order},
            "counts": counts,
            "excluded": excluded,
        }

    # ---------------------------------------------------------------- Color

    def color_convert(
        self, color: str, from_format: str, background: str | None
    ) -> dict[str, Any]:
        from app.services.color_tools import color_convert as _cc

        return _cc(color, from_format, background)
