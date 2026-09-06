"""Data conversion and comparison service (JSON diff/patch, YAML, XML).

All conversions are performed locally and offline. XML parsing is hardened
with ``defusedxml`` (no external entities, no entity-expansion bombs). JSON and
YAML inputs are strictly parsed; non-JSON-safe YAML scalars are converted to
strings or rejected rather than silently dropped.
"""
from __future__ import annotations

import base64
import json
import re
from datetime import date, datetime
from typing import Any
from xml.etree import ElementTree as ET

import yaml
from defusedxml.common import DefusedXmlException as _DefusedXmlException
from defusedxml.ElementTree import ParseError, fromstring

from app.core.exceptions import ValidationError, ResourceLimitError
from app.core.limits import load_json_limited

_MAX_DEPTH = 200
_MAX_XML_NODES = 100_000
_MAX_JSON_NODES = 100_000
_TAG_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")


class DataToolsService:
    """Pure, offline JSON/YAML/XML transformation and comparison tools."""

    # -- shared helpers ------------------------------------------------------

    @staticmethod
    def _type_name(value: Any) -> str:
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, dict):
            return "object"
        if isinstance(value, list):
            return "array"
        if isinstance(value, str):
            return "string"
        return "number"

    @staticmethod
    def _load_json(text: str) -> Any:
        return load_json_limited(
            text,
            max_depth=_MAX_DEPTH,
            max_nodes=_MAX_JSON_NODES,
            error_message="Invalid JSON:",
        )

    @staticmethod
    def _deep_equal(a: Any, b: Any) -> bool:
        return bool(a == b)

    @staticmethod
    def _pointer(parts: list[str]) -> str:
        escaped = [part.replace("~", "~0").replace("/", "~1") for part in parts]
        return "/" + "/".join(escaped)

    def _diff_walk(self, a: Any, b: Any, path: list[str], out: list[dict[str, Any]], depth: int = 0) -> None:
        if depth > _MAX_DEPTH:
            raise ResourceLimitError("JSON document is too deeply nested.")
        if len(out) >= _MAX_JSON_NODES:
            raise ResourceLimitError("JSON diff exceeds the operation limit.")
        if self._deep_equal(a, b):
            return
        if isinstance(a, dict) and isinstance(b, dict):
            for key in sorted(set(a.keys()) | set(b.keys())):
                child = [*path, str(key)]
                if key not in b:
                    out.append({
                        "path": self._pointer(child),
                        "operation": "removed",
                        "before": a[key],
                    })
                elif key not in a:
                    out.append({
                        "path": self._pointer(child),
                        "operation": "added",
                        "after": b[key],
                    })
                else:
                    self._diff_walk(a[key], b[key], child, out, depth + 1)
        elif isinstance(a, list) and isinstance(b, list):
            shared = min(len(a), len(b))
            for i in range(shared):
                self._diff_walk(a[i], b[i], [*path, str(i)], out, depth + 1)
            for i in range(shared, len(a)):
                out.append({
                    "path": self._pointer([*path, str(i)]),
                    "operation": "removed",
                    "before": a[i],
                })
            for i in range(shared, len(b)):
                out.append({
                    "path": self._pointer([*path, str(i)]),
                    "operation": "added",
                    "after": b[i],
                })
        else:
            out.append({
                "path": self._pointer(path),
                "operation": "modified",
                "before": a,
                "after": b,
            })

    def _patch_walk(self, a: Any, b: Any, path: list[str], out: list[dict[str, Any]], depth: int = 0) -> None:
        if depth > _MAX_DEPTH:
            raise ResourceLimitError("JSON document is too deeply nested.")
        if len(out) >= _MAX_JSON_NODES:
            raise ResourceLimitError("JSON patch exceeds the operation limit.")
        if self._deep_equal(a, b):
            return
        if isinstance(a, dict) and isinstance(b, dict):
            for key in sorted(set(a.keys()) | set(b.keys())):
                child = [*path, str(key)]
                if key not in b:
                    out.append({"op": "remove", "path": self._pointer(child)})
                elif key not in a:
                    out.append({"op": "add", "path": self._pointer(child), "value": b[key]})
                else:
                    self._patch_walk(a[key], b[key], child, out, depth + 1)
        elif isinstance(a, list) and isinstance(b, list):
            shared = min(len(a), len(b))
            for i in range(shared):
                self._patch_walk(a[i], b[i], [*path, str(i)], out, depth + 1)
            base = self._pointer(path)
            for i in range(shared, len(b)):
                out.append({"op": "add", "path": f"{base}/{i}", "value": b[i]})
            for i in range(len(a) - 1, shared - 1, -1):
                out.append({"op": "remove", "path": f"{base}/{i}"})
        else:
            out.append({"op": "replace", "path": self._pointer(path), "value": b})

    @staticmethod
    def _apply_patch(target: Any, patch: list[dict[str, Any]]) -> Any:
        """Apply an RFC 6902 patch locally (add/remove/replace subset)."""
        doc = json.loads(json.dumps(target))

        def resolve(parts: list[str]) -> Any:
            node: Any = doc
            for part in parts:
                if isinstance(node, dict):
                    node = node[part]
                elif isinstance(node, list):
                    node = node[int(part)]
                else:
                    raise KeyError("path component beyond a scalar")
            return node

        for op_in in patch:
            op: dict[str, Any] = dict(op_in)
            raw_path = str(op["path"])
            parts: list[str] = []
            if raw_path != "":
                parts = [p.replace("~1", "/").replace("~0", "~") for p in raw_path[1:].split("/")
                         if p != ""]
            tail = parts[-1] if parts else None
            parent = resolve(parts[:-1]) if parts else None
            op_name = str(op.get("op"))
            if op_name == "remove":
                if isinstance(parent, dict) and tail is not None:
                    parent.pop(tail)
                elif isinstance(parent, list) and tail is not None:
                    parent.pop(int(tail))
            elif op_name == "add":
                if parent is None:
                    doc = op["value"]
                elif isinstance(parent, dict) and tail is not None:
                    parent[tail] = op["value"]
                elif isinstance(parent, list) and tail is not None:
                    parent.insert(int(tail), op["value"])
            elif op_name == "replace":
                if parent is None:
                    doc = op["value"]
                elif isinstance(parent, dict) and tail is not None:
                    parent[tail] = op["value"]
                elif isinstance(parent, list) and tail is not None:
                    parent[int(tail)] = op["value"]
        return doc

    # -- JSON diff / patch ---------------------------------------------------

    def json_diff(self, document_a: str, document_b: str) -> dict[str, Any]:
        a = self._load_json(document_a)
        b = self._load_json(document_b)
        changes: list[dict[str, Any]] = []
        self._diff_walk(a, b, [], changes)
        counts = {"added": 0, "removed": 0, "modified": 0}
        for change in changes:
            counts[change["operation"]] += 1
        return {
            "equal": not changes,
            "added": counts["added"],
            "removed": counts["removed"],
            "modified": counts["modified"],
            "total_changes": len(changes),
            "changes": changes,
        }

    def json_patch(self, document_a: str, document_b: str) -> dict[str, Any]:
        a = self._load_json(document_a)
        b = self._load_json(document_b)
        patch: list[dict[str, Any]] = []
        self._patch_walk(a, b, [], patch)
        transformable = False
        try:
            transformable = self._deep_equal(self._apply_patch(a, patch), b)
        except Exception:
            transformable = False
        return {"patch": patch, "operation_count": len(patch), "transformable": transformable}

    # -- YAML conversion -----------------------------------------------------

    @staticmethod
    def _json_safe(
        value: Any,
        depth: int = 0,
        seen: set[int] | None = None,
        counter: list[int] | None = None,
    ) -> Any:
        seen = seen if seen is not None else set()
        counter = counter if counter is not None else [0]
        counter[0] += 1
        if counter[0] > _MAX_JSON_NODES:
            raise ResourceLimitError("YAML document exceeds the node limit.")
        if depth > _MAX_DEPTH:
            raise ResourceLimitError("YAML document is too deeply nested.")
        if value is None or isinstance(value, (bool, str, int, float)):
            return value
        marker = id(value)
        if marker in seen:
            raise ValidationError("YAML aliases produced a recursive structure.")
        if isinstance(value, dict):
            seen.add(marker)
            result = {
                str(k): DataToolsService._json_safe(v, depth + 1, seen, counter)
                for k, v in value.items()
            }
            seen.remove(marker)
            return result
        if isinstance(value, (list, tuple, set)):
            seen.add(marker)
            result = [
                DataToolsService._json_safe(v, depth + 1, seen, counter) for v in value
            ]
            seen.remove(marker)
            return result
        if isinstance(value, (datetime, date)):
            return value.isoformat()
        if isinstance(value, bytes):
            return base64.b64encode(value).decode("ascii")
        raise ValidationError(f"Unsupported YAML scalar type: {type(value).__name__}")

    def yaml_convert(self, direction: str, input_text: str) -> dict[str, Any]:
        if direction == "yaml_to_json":
            try:
                loaded = yaml.safe_load(input_text)
            except yaml.YAMLError as exc:
                raise ValidationError(f"Invalid YAML: {exc}") from exc
            value = self._json_safe(loaded)
            output = json.dumps(value, ensure_ascii=False, indent=2)
            return {"valid": True, "direction": direction, "output": output, "value": value,
                    "type": self._type_name(value), "error": None}
        value = self._load_json(input_text)
        try:
            output = yaml.safe_dump(
                value, sort_keys=False, allow_unicode=True, default_flow_style=False
            )
        except yaml.YAMLError as exc:
            raise ValidationError(f"Could not serialize to YAML: {exc}") from exc
        return {"valid": True, "direction": direction, "output": output, "value": value,
                "type": self._type_name(value), "error": None}

    # -- XML conversion ------------------------------------------------------

    def _xml_node_to_obj(self, elem: Any, counter: list[int]) -> dict[str, Any]:
        counter[0] += 1
        if counter[0] > _MAX_XML_NODES:
            raise ValidationError("XML document contains too many elements.")
        result: dict[str, Any] = {}
        for name, attr_value in elem.attrib.items():
            result[f"@{name}"] = attr_value
        text = elem.text
        if text is not None and text.strip():
            result["#text"] = text.strip()
        children: list[tuple[str, Any]] = []
        for child in elem:
            children.append((child.tag, child))
        for tag, child in children:
            result.setdefault(tag, []).append(self._xml_node_to_obj(child, counter))
        return result

    @staticmethod
    def _validate_tag(tag: str) -> None:
        if not _TAG_RE.match(tag):
            raise ValidationError(f"Invalid XML tag name: {tag!r}")

    def _build_element(self, tag: str, value: Any, counter: list[int], depth: int) -> ET.Element:
        if depth > _MAX_DEPTH:
            raise ValidationError("JSON document is too deeply nested for XML conversion.")
        self._validate_tag(tag)
        counter[0] += 1
        if counter[0] > _MAX_XML_NODES:
            raise ValidationError("Document produces too many XML elements.")
        elem = ET.Element(tag)
        if isinstance(value, dict):
            text = value.get("#text")
            for key, item in value.items():
                if key.startswith("@"):
                    attr_name = key[1:]
                    if not _TAG_RE.match(attr_name):
                        raise ValidationError(f"Invalid XML attribute name: {attr_name!r}")
                    if not isinstance(item, (str, int, float, bool)):
                        continue
                    elem.set(attr_name, str(item).lower() if isinstance(item, bool) else str(item))
            if text is not None and isinstance(text, (str, int, float)):
                elem.text = str(text)
            for key, item in value.items():
                if key.startswith("@") or key == "#text":
                    continue
                if isinstance(item, list):
                    for sub in item:
                        elem.append(self._build_element(key, sub, counter, depth + 1))
                else:
                    elem.append(self._build_element(key, item, counter, depth + 1))
        elif isinstance(value, list):
            raise ValidationError(
                "Top-level arrays cannot be converted to XML without a container tag."
            )
        elif value is None:
            pass
        elif isinstance(value, bool):
            elem.text = "true" if value else "false"
        else:
            elem.text = str(value)
        return elem

    def xml_convert(self, direction: str, input_text: str, root_name: str) -> dict[str, Any]:
        if direction == "xml_to_json":
            try:
                root = fromstring(input_text)
            except (_DefusedXmlException, ParseError) as exc:
                raise ValidationError(f"Invalid XML: {exc}") from exc
            counter = [0]
            value = {root.tag: self._xml_node_to_obj(root, counter)}
            output = json.dumps(value, ensure_ascii=False, indent=2)
            return {"valid": True, "direction": direction, "output": output, "value": value,
                    "root": root.tag, "error": None}

        data = self._load_json(input_text)
        if isinstance(data, list):
            raise ValidationError(
                "A JSON array cannot be the XML root; wrap it in an object first."
            )
        root = root_name
        if isinstance(data, dict) and not root_name:
            if len(data) == 1:
                root = str(next(iter(data.keys())))
                content = data[root]
            else:
                root = "root"
                content = data
        else:
            root = root_name or "root"
            content = data
        self._validate_tag(root)
        counter = [0]
        elem = self._build_element(root, content, counter, 0)
        try:
            output = ET.tostring(elem, encoding="unicode")
        except (ValueError, TypeError) as exc:
            raise ValidationError(f"Could not serialize XML: {exc}") from exc
        return {"valid": True, "direction": direction, "output": output + "\n", "value": data,
                "root": root, "error": None}
