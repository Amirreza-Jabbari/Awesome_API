"""Data-conversion endpoints: JSON diff/patch, YAML and XML conversion."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from app.core.dependencies import get_data_tools_service
from app.schemas.data_tools import (
    JSONDiffRequest,
    JSONDiffResponse,
    JSONPatchRequest,
    JSONPatchResponse,
    XMLConvertRequest,
    XMLConvertResponse,
    YAMLConvertRequest,
    YAMLConvertResponse,
)
from app.services.data_tools_service import DataToolsService

router = APIRouter()


# ── JSON Diff ────────────────────────────────────────────────────────────────

@router.post(
    "/json/diff",
    response_model=JSONDiffResponse,
    tags=["Data & Encoding"],
    summary="Diff two JSON documents",
    description=(
        "Recursively compares two JSON documents and reports added, removed and "
        "modified values with JSON-pointer paths. Fully local, with no size or "
        "depth limits beyond a 2 MB input cap."
    ),
)
async def json_diff(
    payload: JSONDiffRequest,
    service: DataToolsService = Depends(get_data_tools_service),
) -> dict[str, Any]:
    return service.json_diff(payload.document_a, payload.document_b)


# ── JSON Patch Generator ─────────────────────────────────────────────────────

@router.post(
    "/json/patch",
    response_model=JSONPatchResponse,
    tags=["Data & Encoding"],
    summary="Generate an RFC 6902 JSON Patch",
    description=(
        "Produces a minimal, standards-compliant RFC 6902 JSON Patch that "
        "transforms document_a into document_b (add/remove/replace operations "
        "with JSON-Pointer paths). The patch is applied locally to confirm it "
        "transforms cleanly before it is returned."
    ),
)
async def json_patch(
    payload: JSONPatchRequest,
    service: DataToolsService = Depends(get_data_tools_service),
) -> dict[str, Any]:
    return service.json_patch(payload.document_a, payload.document_b)


# ── YAML ↔ JSON Converter ────────────────────────────────────────────────────

@router.post(
    "/yaml/convert",
    response_model=YAMLConvertResponse,
    tags=["Data & Encoding"],
    summary="Convert between YAML and JSON",
    description=(
        "Directional converter between YAML and JSON intended for config, "
        "OpenAPI and pipeline snippets. YAML is read with a safe loader (no "
        "arbitrary object construction); non-JSON scalars such as dates are "
        "rendered as ISO-8601 strings."
    ),
)
async def yaml_convert(
    payload: YAMLConvertRequest,
    service: DataToolsService = Depends(get_data_tools_service),
) -> dict[str, Any]:
    return service.yaml_convert(payload.direction, payload.input)


# ── XML ↔ JSON Converter ─────────────────────────────────────────────────────

@router.post(
    "/xml/convert",
    response_model=XMLConvertResponse,
    tags=["Data & Encoding"],
    summary="Convert between XML and JSON",
    description=(
        "Directional converter between XML and JSON. XML input is parsed with "
        "defusedxml, blocking XXE, external-entity and entity-expansion "
        "attacks. XML elements become `{tag: {...}}` objects, attributes are "
        "prefixed with `@`, and text content lives under `#text` so the "
        "conversion is lossless and round-trippable."
    ),
)
async def xml_convert(
    payload: XMLConvertRequest,
    service: DataToolsService = Depends(get_data_tools_service),
) -> dict[str, Any]:
    return service.xml_convert(payload.direction, payload.input, payload.root_name)
