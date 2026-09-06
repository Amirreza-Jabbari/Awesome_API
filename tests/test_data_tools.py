"""Data-tool service tests: JSON diff/patch, YAML and XML conversion (offline)."""

from __future__ import annotations

import pytest
from app.core.exceptions import ValidationError
from app.services.data_tools_service import DataToolsService


@pytest.fixture
def service() -> DataToolsService:
    return DataToolsService()


def test_json_diff_equal(service) -> None:
    result = service.json_diff('{"a": 1}', '{"a": 1}')
    assert result["equal"] is True
    assert result["total_changes"] == 0


def test_json_diff_reports_added_removed_modified(service) -> None:
    result = service.json_diff('{"a": 1, "b": 2}', '{"a": 9, "c": 3}')
    ops = {(c["operation"]) for c in result["changes"]}
    assert ops == {"added", "removed", "modified"}


def test_json_diff_array_index_paths(service) -> None:
    result = service.json_diff("[1, 2]", "[1, 3]")
    assert result["total_changes"] == 1
    assert result["changes"][0]["path"] == "/1"


def test_json_diff_invalid_json(service) -> None:
    with pytest.raises(ValidationError):
        service.json_diff("{broken", "{}")


def test_json_patch_rfc6902_shape(service) -> None:
    result = service.json_patch('{"name": "x"}', '{"name": "y"}')
    assert result["transformable"] is True
    assert result["operation_count"] == len(result["patch"])
    assert result["patch"][0]["op"] == "replace"


def test_json_patch_nested_array(service) -> None:
    result = service.json_patch('{"items": [1, 2]}', '{"items": [1]}')
    assert result["transformable"] is True
    ops = {p["op"] for p in result["patch"]}
    assert "remove" in ops


def test_json_patch_apply_equals_target(service) -> None:
    a = '{"a": {"b": [1, 2, 3]}, "c": "keep"}'
    b = '{"a": {"b": [1, 9]}, "c": "keep", "d": true}'
    result = service.json_patch(a, b)
    assert result["transformable"] is True


def test_yaml_to_json_roundtrip(service) -> None:
    result = service.yaml_convert("yaml_to_json", "name: Alice\nage: 42\n")
    assert result["valid"] is True
    assert result["type"] == "object"
    assert result["value"]["name"] == "Alice"


def test_yaml_dates_become_iso_strings(service) -> None:
    result = service.yaml_convert("yaml_to_json", "day: 2026-09-05\n")
    assert result["value"]["day"] == "2026-09-05"


def test_json_to_yaml(service) -> None:
    result = service.yaml_convert("json_to_yaml", '{"a": 1, "b": [1, 2]}')
    assert result["valid"] is True
    assert "a: 1" in result["output"]


def test_yaml_rejects_python_object_tags(service) -> None:
    with pytest.raises(ValidationError):
        service.yaml_convert("yaml_to_json", "!!python/object/apply:os.system [ls]")


def test_yaml_invalid_input(service) -> None:
    with pytest.raises(ValidationError):
        service.yaml_convert("yaml_to_json", ":: not yaml ::")


def test_json_to_xml_attributes_and_text(service) -> None:
    result = service.xml_convert(
        "json_to_xml",
        '{"root": {"@id": "1", "#text": "hello"}}',
        "",
    )
    assert result["valid"] is True
    assert result["root"] == "root"
    assert 'id="1"' in result["output"]
    assert "hello" in result["output"]


def test_xml_to_json_roundtrip(service) -> None:
    result = service.xml_convert("xml_to_json", "<root><id>5</id></root>", "")
    assert result["valid"] is True
    assert result["value"]["root"]["id"] == [{"#text": "5"}]


def test_xml_entity_expansion_blocked(service) -> None:
    bomb = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE r [<!ENTITY e "boom">]>'
        "<r>&e;</r>"
    )
    with pytest.raises(ValidationError):
        service.xml_convert("xml_to_json", bomb, "")


def test_xml_invalid_input(service) -> None:
    with pytest.raises(ValidationError):
        service.xml_convert("xml_to_json", "<unclosed>", "")


def test_json_to_xml_invalid_tag_names(service) -> None:
    with pytest.raises(ValidationError):
        service.xml_convert("json_to_xml", '{"bad tag!": {"x": 1}}', "")
