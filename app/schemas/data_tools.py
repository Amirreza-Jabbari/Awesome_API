"""Schemas for data-conversion and comparison utilities (JSON, YAML, XML)."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class JSONDiffRequest(BaseModel):
    document_a: str = Field(max_length=2_000_000)
    document_b: str = Field(max_length=2_000_000)


class DiffChange(BaseModel):
    path: str
    operation: Literal["added", "removed", "modified"]
    before: Any = None
    after: Any = None


class JSONDiffResponse(BaseModel):
    equal: bool
    added: int
    removed: int
    modified: int
    total_changes: int
    changes: list[DiffChange]


class JSONPatchRequest(BaseModel):
    document_a: str = Field(max_length=2_000_000)
    document_b: str = Field(max_length=2_000_000)


class JSONPatchResponse(BaseModel):
    patch: list[dict[str, Any]]
    operation_count: int
    transformable: bool


class YAMLConvertRequest(BaseModel):
    direction: Literal["yaml_to_json", "json_to_yaml"]
    input: str = Field(max_length=2_000_000)


class YAMLConvertResponse(BaseModel):
    valid: bool
    direction: str
    output: str | None = None
    value: Any = None
    type: str | None = None
    error: str | None = None


class XMLConvertRequest(BaseModel):
    direction: Literal["xml_to_json", "json_to_xml"]
    input: str = Field(max_length=2_000_000)
    root_name: str = Field(default="", max_length=64)


class XMLConvertResponse(BaseModel):
    valid: bool
    direction: str
    output: str | None = None
    value: Any = None
    root: str | None = None
    error: str | None = None
