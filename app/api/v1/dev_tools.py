"""Developer endpoints: SQL, SemVer, changelog, color and mock-data tools."""
from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends

from app.core.dependencies import get_dev_tools_service, get_mock_data_service
from app.schemas.dev_tools import (
    ChangelogRequest,
    ChangelogResponse,
    ColorConvertRequest,
    ColorConvertResponse,
    MockDataRequest,
    MockDataResponse,
    OpenAPIMockRequest,
    OpenAPIMockResponse,
    SemVerRequest,
    SemVerResponse,
    SQLFormatRequest,
    SQLFormatResponse,
    SQLMinifyRequest,
    SQLMinifyResponse,
    SQLValidateRequest,
    SQLValidateResponse,
)
from app.services.dev_tools_service import DevToolsService
from app.services.mock_data_service import MockDataGenerator

router = APIRouter()


# ── SQL Formatter ────────────────────────────────────────────────────────────

@router.post(
    "/sql/format",
    response_model=SQLFormatResponse,
    tags=["Developer Tools"],
    summary="Format SQL statements",
    description=(
        "Pretty-prints SQL with configurable keyword case and indentation. "
        "Static analysis only - the SQL is never executed or sent anywhere."
    ),
)
async def sql_format(
    payload: SQLFormatRequest,
    service: DevToolsService = Depends(get_dev_tools_service),
) -> dict[str, Any]:
    return service.sql_format(
        payload.sql, payload.keyword_case, payload.indent,
        payload.strip_comments, payload.reindent,
    )


# ── SQL Minifier ─────────────────────────────────────────────────────────────

@router.post(
    "/sql/minify",
    response_model=SQLMinifyResponse,
    tags=["Developer Tools"],
    summary="Minify SQL statements",
    description=(
        "Strips comments and unnecessary whitespace to produce a compact SQL "
        "string, reporting how many comments were removed. Static only - never "
        "executed."
    ),
)
async def sql_minify(
    payload: SQLMinifyRequest,
    service: DevToolsService = Depends(get_dev_tools_service),
) -> dict[str, Any]:
    return service.sql_minify(payload.sql, payload.keyword_case, payload.strip_comments)


# ── SQL Validator ────────────────────────────────────────────────────────────

@router.post(
    "/sql/validate",
    response_model=SQLValidateResponse,
    tags=["Developer Tools"],
    summary="Validate SQL structure",
    description=(
        "Checks SQL for unbalanced parentheses and parse failures using a "
        "syntax tokenizer. Structural validation only - it does not execute "
        "the statement or contact a database."
    ),
)
async def sql_validate(
    payload: SQLValidateRequest,
    service: DevToolsService = Depends(get_dev_tools_service),
) -> dict[str, Any]:
    return service.sql_validate(payload.sql)


# ── SemVer Analyzer ──────────────────────────────────────────────────────────

@router.post(
    "/semver/analyze",
    response_model=SemVerResponse,
    tags=["Developer Tools"],
    summary="Analyze a semantic version",
    description=(
        "Parses a SemVer 2.0.0 version into its components, compares it to an "
        "optional second version with a breaking-change hint, and tests it "
        "against a supported range operator (^, ~, >=, <=, =, >, < or ||)."
    ),
)
async def semver_analyze(
    payload: SemVerRequest,
    service: DevToolsService = Depends(get_dev_tools_service),
) -> dict[str, Any]:
    return service.semver(payload.version, payload.other, payload.range)


# ── Changelog Generator ──────────────────────────────────────────────────────

@router.post(
    "/changelog/generate",
    response_model=ChangelogResponse,
    tags=["Developer Tools"],
    summary="Generate a Keep-a-Changelog document",
    description=(
        "Groups conventional-commit entries into Keep-a-Changelog sections, "
        "separates breaking changes, and renders markdown for the given version "
        "and date (or an explicit unreleased heading)."
    ),
)
async def changelog_generate(
    payload: ChangelogRequest,
    service: DevToolsService = Depends(get_dev_tools_service),
) -> dict[str, Any]:
    commits = [c.model_dump() for c in payload.commits]
    return service.changelog(
        commits, payload.version, payload.date, payload.title, payload.unreleased,
    )


# ── Color Converter ──────────────────────────────────────────────────────────

@router.post(
    "/color/convert",
    response_model=ColorConvertResponse,
    tags=["Developer Tools"],
    summary="Convert between color formats",
    description=(
        "Converts a color between hex, rgb(a), hsl(a) and hsv(a), returns the "
        "closest CSS named color, and computes WCAG relative luminance and an "
        "optional contrast ratio against a background color."
    ),
)
async def color_convert(
    payload: ColorConvertRequest,
    service: DevToolsService = Depends(get_dev_tools_service),
) -> dict[str, Any]:
    return service.color_convert(payload.color, payload.from_format, payload.background)


# ── Mock Data Generator ──────────────────────────────────────────────────────

@router.post(
    "/mock/generate",
    response_model=MockDataResponse,
    tags=["Developer Tools"],
    summary="Generate mock JSON data",
    description=(
        "Produces deterministic mock JSON from either a JSON-Schema subset or "
        "a flat field definition. Generation is seeded, depth-capped and "
        "bounded by a global node budget; realistic values are produced for "
        "formats like email, URL, UUID and date-time."
    ),
)
async def mock_generate(
    payload: MockDataRequest,
    service: MockDataGenerator = Depends(get_mock_data_service),
) -> dict[str, Any]:
    generator = service
    if payload.schema_ is not None:
        value, summary = generator.generate_schema(
            payload.schema_,
            seed=payload.seed,
            max_array_length=payload.max_array_length,
            max_depth=payload.max_depth,
        )
    else:
        fields = [f.model_dump(exclude_none=True) for f in payload.fields or []]
        value, summary = generator.generate_fields(
            fields,
            seed=payload.seed,
            max_array_length=payload.max_array_length,
            max_depth=payload.max_depth,
        )
    return {
        "value": value,
        "json": json.dumps(value, ensure_ascii=False, indent=4),
        "type": _value_type(value),
        "node_count": summary["node_count"],
        "truncated": bool(summary["truncated"]),
        "warning": "Array length was truncated to respect max_array_length."
                    if summary["truncated"] else None,
    }


# ── OpenAPI Mock Generator ───────────────────────────────────────────────────

@router.post(
    "/mock/openapi",
    response_model=OpenAPIMockResponse,
    tags=["Developer Tools"],
    summary="Generate mock data from an OpenAPI document",
    description=(
        "Parses an OpenAPI 3.x document (JSON or YAML), selects a path and "
        "(optionally) method, picks the first 2xx response schema, and generates "
        "deterministic sample data for it."
    ),
)
async def mock_openapi(
    payload: OpenAPIMockRequest,
    service: MockDataGenerator = Depends(get_mock_data_service),
) -> dict[str, Any]:
    generator = service
    result = generator.generate_openapi(
        payload.document, payload.path, payload.method,
        seed=payload.seed,
        max_array_length=payload.max_array_length,
        max_depth=payload.max_depth,
    )
    if result["valid"] and result.get("json") is None:
        result["json"] = json.dumps(result.get("content"), ensure_ascii=False, indent=4)
    return result


def _value_type(value: Any) -> str:
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    return "string"
