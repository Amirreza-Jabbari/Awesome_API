"""Schemas for developer utilities (SQL, SemVer, changelog, color, mock data)."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class SQLFormatRequest(BaseModel):
    sql: str = Field(max_length=2_000_000)
    keyword_case: Literal["upper", "lower"] = "upper"
    indent: int = Field(default=2, ge=1, le=8)
    strip_comments: bool = False
    reindent: bool = True


class SQLFormatResponse(BaseModel):
    valid: bool
    formatted: str | None = None
    statement_count: int = 0
    issues: list[str] = Field(default_factory=list)
    error: str | None = None


class SQLMinifyRequest(BaseModel):
    sql: str = Field(max_length=2_000_000)
    keyword_case: Literal["upper", "lower"] = "upper"
    strip_comments: bool = True


class SQLMinifyResponse(BaseModel):
    valid: bool
    minified: str | None = None
    removed_comments: int = 0
    statement_count: int = 0
    original_length: int = 0
    minified_length: int = 0
    error: str | None = None


class SQLValidateRequest(BaseModel):
    sql: str = Field(max_length=2_000_000)


class SQLValidateResponse(BaseModel):
    valid: bool
    statement_count: int = 0
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class SemVerRequest(BaseModel):
    version: str = Field(min_length=1, max_length=128)
    other: str | None = Field(default=None, max_length=128)
    range: str | None = Field(default=None, max_length=256)


class SemVerComparison(BaseModel):
    comparable: bool = False
    other: str | None = None
    value: int | None = None
    is_breaking: bool | None = None
    reason: str | None = None


class SemVerRangeResult(BaseModel):
    valid: bool = True
    matches: bool | None = None
    error: str | None = None


class SemVerResponse(BaseModel):
    valid: bool
    error: str | None = None
    major: int | None = None
    minor: int | None = None
    patch: int | None = None
    prerelease: str | None = None
    build: str | None = None
    core: str | None = None
    is_prerelease: bool = False
    comparison: SemVerComparison | None = None
    range_result: SemVerRangeResult | None = None


class ChangelogCommit(BaseModel):
    hash: str | None = Field(default=None, max_length=64)
    type: Literal[
        "feat", "fix", "docs", "style", "refactor", "perf", "test", "build", "ci",
        "chore", "other",
    ] = "other"
    scope: str | None = Field(default=None, max_length=64)
    description: str = Field(min_length=1, max_length=500)
    breaking: bool = False


class ChangelogRequest(BaseModel):
    commits: list[ChangelogCommit] = Field(min_length=1, max_length=1000)
    version: str | None = Field(default=None, max_length=64)
    date: str | None = Field(default=None, max_length=64)
    title: str | None = Field(default=None, max_length=200)
    unreleased: bool = False


class ChangelogResponse(BaseModel):
    markdown: str
    sections: dict[str, list[str]] = Field(default_factory=dict)
    counts: dict[str, int] = Field(default_factory=dict)
    excluded: int = 0


class ColorConvertRequest(BaseModel):
    color: str = Field(min_length=1, max_length=64)
    from_format: Literal["auto", "hex", "rgb", "rgba", "hsl", "hsla", "hsv", "hsva"] = "auto"
    background: str | None = Field(default=None, max_length=64)


class ColorRGB(BaseModel):
    r: int
    g: int
    b: int


class ColorRGBA(BaseModel):
    r: int
    g: int
    b: int
    a: float


class ColorHSL(BaseModel):
    h: float
    s: float
    lightness: float


class ColorHSV(BaseModel):
    h: float
    s: float
    v: float


class ColorConvertResponse(BaseModel):
    valid: bool
    error: str | None = None
    from_format: str | None = None
    hex: str | None = None
    rgb: ColorRGB | None = None
    rgba: ColorRGBA | None = None
    hsl: ColorHSL | None = None
    hsv: ColorHSV | None = None
    css: dict[str, str] = Field(default_factory=dict)
    luminance: float | None = None
    contrast: float | None = None
    notes: list[str] = Field(default_factory=list)


MockFieldType = Literal[
    "string", "integer", "number", "boolean", "null", "object", "array", "enum",
    "datetime", "date", "uuid", "email", "url", "ipv4", "ipv6", "hostname",
    "username", "first_name", "last_name", "company", "color", "phone",
]


class MockField(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    type: MockFieldType = "string"
    format: str = "none"
    enum: list[Any] | None = None
    minimum: int | None = Field(default=None, ge=-(2**63), le=2**63 - 1)
    maximum: int | None = Field(default=None, ge=-(2**63), le=2**63 - 1)
    min_length: int = Field(default=0, ge=0, le=1024)
    max_length: int = Field(default=32, ge=1, le=4096)
    min_items: int = Field(default=0, ge=0, le=1000)
    max_items: int = Field(default=5, ge=1, le=1000)
    item_type: MockFieldType | None = None
    item_format: str = "none"
    nullable: bool = False
    default: Any = None


class MockDataRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    schema_: dict[str, Any] | None = Field(default=None, alias="schema")
    fields: list[MockField] | None = None
    seed: int | None = Field(default=None, ge=0, le=2**63 - 1)
    max_array_length: int = Field(default=10, ge=1, le=100)
    max_depth: int = Field(default=6, ge=1, le=12)

    @model_validator(mode="after")
    def exactly_one_source(self) -> MockDataRequest:
        if (self.schema_ is None) == (self.fields is None):
            raise ValueError("Provide exactly one of 'schema' or 'fields'.")
        return self


class MockDataResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    value: Any
    json_: str = Field(alias="json")
    type: str
    node_count: int
    truncated: bool = False
    warning: str | None = None


class OpenAPIMockRequest(BaseModel):
    document: str = Field(max_length=2_000_000)
    path: str = Field(min_length=1, max_length=512)
    method: str | None = Field(default=None, max_length=16)
    seed: int | None = Field(default=None, ge=0, le=2**63 - 1)
    max_array_length: int = Field(default=10, ge=1, le=100)
    max_depth: int = Field(default=6, ge=1, le=12)


class OpenAPIMockResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    valid: bool
    error: str | None = None
    operation_id: str | None = None
    path: str | None = None
    method: str | None = None
    status_code: int | None = None
    content_type: str | None = None
    content: Any = None
    json_: str | None = Field(default=None, alias="json")
    matched_schema: str | None = None
