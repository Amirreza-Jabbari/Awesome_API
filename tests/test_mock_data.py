"""Mock-data generator service tests: schema/fields/OpenAPI generation (offline)."""

from __future__ import annotations

import pytest
from app.core.exceptions import ValidationError
from app.services.mock_data_service import MockDataGenerator

USER_SCHEMA = {
    "type": "object",
    "properties": {
        "id": {"type": "integer"},
        "active": {"type": "boolean"},
        "email": {"type": "string", "format": "email"},
        "tags": {"type": "array", "items": {"type": "string"}},
    },
}


def test_generate_schema_types() -> None:
    value, _ = MockDataGenerator(seed=1).generate_schema(USER_SCHEMA)
    assert isinstance(value["id"], int)
    assert isinstance(value["active"], bool)
    assert "@" in value["email"]
    assert isinstance(value["tags"], list)


def test_generate_schema_seed_determinism() -> None:
    a, _ = MockDataGenerator().generate_schema(USER_SCHEMA, seed=42)
    b, _ = MockDataGenerator().generate_schema(USER_SCHEMA, seed=42)
    assert a == b


def test_generate_schema_different_seeds_differ() -> None:
    schema = {"type": "array", "items": {"type": "integer"}}
    a, _ = MockDataGenerator().generate_schema(schema, seed=1)
    b, _ = MockDataGenerator().generate_schema(schema, seed=2)
    assert a != b


def test_generate_schema_respects_max_array_length() -> None:
    schema = {"type": "array", "items": {"type": "integer"}}
    value, _ = MockDataGenerator().generate_schema(schema, seed=5, max_array_length=3)
    assert len(value) <= 3


def test_generate_schema_summary_counts() -> None:
    schema = {"type": "object", "properties": {"a": {"type": "integer"}}}
    _, summary = MockDataGenerator(seed=1).generate_schema(schema)
    assert summary["node_count"] >= 2
    assert summary["truncated"] is False


def test_generate_schema_blank_type_is_string() -> None:
    value, _ = MockDataGenerator(seed=1).generate_schema({"type": "gizmo"})
    assert isinstance(value, str)


def test_generate_fields() -> None:
    fields = [
        {"name": "name", "type": "string"},
        {"name": "count", "type": "integer"},
        {"name": "uuid", "type": "string", "format": "uuid"},
    ]
    value, _ = MockDataGenerator(seed=1).generate_fields(fields)
    assert isinstance(value["name"], str)
    assert isinstance(value["count"], int)
    assert len(value["uuid"]) == 36


def test_generate_fields_empty_list() -> None:
    with pytest.raises(ValidationError):
        MockDataGenerator().generate_fields([])


def test_generate_fields_missing_name() -> None:
    with pytest.raises(ValidationError):
        MockDataGenerator().generate_fields([{"type": "string"}])


def test_generate_openapi_from_yaml() -> None:
    doc = (
        "openapi: 3.0.3\n"
        "info:\n  title: Demo\n  version: 1.0.0\n"
        "paths:\n  /users:\n    get:\n      responses:\n        '200':\n"
        "          description: ok\n          content:\n            application/json:\n"
        "              schema:\n                type: object\n"
        "                properties:\n                  name:\n                    type: string\n"
    )
    result = MockDataGenerator().generate_openapi(doc, "/users", "get", seed=3)
    assert result["valid"] is True
    assert result["status_code"] == 200
    assert result["content_type"] == "application/json"
    assert isinstance(result["content"]["name"], str)


def test_generate_openapi_invalid_document() -> None:
    with pytest.raises(ValidationError):
        MockDataGenerator().generate_openapi("not: [valid", "/x", None, seed=1)


def test_generate_openapi_missing_path() -> None:
    doc = '{"openapi": "3.0.3", "info": {"title": "t", "version": "1.0"}, "paths": {}}'
    with pytest.raises(ValidationError):
        MockDataGenerator().generate_openapi(doc, "/nope", None, seed=1)


def test_generate_openapi_method_required_for_multiple() -> None:
    doc = (
        '{"openapi": "3.0.3", "info": {"title": "t", "version": "1.0"}, '
        '"paths": {"/x": {"get": {"responses": {"200": {"description": "ok"}}}, '
        '"post": {"responses": {"200": {"description": "ok"}}}}}}'
    )
    with pytest.raises(ValidationError):
        MockDataGenerator().generate_openapi(doc, "/x", None, seed=1)
