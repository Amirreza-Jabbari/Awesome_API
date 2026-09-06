"""Deterministic mock-data generation service.

Generates realistic JSON test data from either a JSON-Schema subset or a flat
field definition, and from OpenAPI documents. Generation is fully local,
bounded (array length, nesting depth and a global node budget) and seedable so
tests and demos stay reproducible.
"""
from __future__ import annotations

import datetime as _dt
import json
import random
import string
import uuid as _uuid
from typing import Any

import yaml

from app.core.exceptions import ValidationError

_MAX_NODES = 5_000
_MAX_INT = 2**31
_MAX_DEPTH = 40

_TYPE_ALIASES = {
    "str": "string",
    "int": "integer",
    "float": "number",
    "bool": "boolean",
}


class MockDataGenerator:
    """Bounded, seedable JSON generator for schemas, fields and OpenAPI."""

    def __init__(
        self,
        seed: int | None = None,
        max_array_length: int = 10,
        max_depth: int = 6,
    ) -> None:
        self._seed = seed
        self._rng = random.Random(seed)
        self._node_count = 0
        self._max_array_length = max(1, min(100, max_array_length))
        self._max_depth = max(1, min(12, max_depth))
        self._truncated = False

    def _variant(
        self,
        seed: int | None = None,
        max_array_length: int | None = None,
        max_depth: int | None = None,
    ) -> MockDataGenerator:
        if seed is None and max_array_length is None and max_depth is None:
            return self
        return MockDataGenerator(
            seed=self._seed if seed is None else seed,
            max_array_length=(
                self._max_array_length if max_array_length is None else max_array_length
            ),
            max_depth=self._max_depth if max_depth is None else max_depth,
        )

    # ------------------------------------------------------------ generation

    def generate_schema(
        self,
        schema: dict[str, Any],
        seed: int | None = None,
        max_array_length: int | None = None,
        max_depth: int | None = None,
    ) -> tuple[Any, dict[str, Any]]:
        gen = self._variant(seed, max_array_length, max_depth)
        value = gen._from_schema(schema, 0)
        return value, gen._summary(value)

    def generate_fields(
        self,
        fields: list[dict[str, Any]],
        seed: int | None = None,
        max_array_length: int | None = None,
        max_depth: int | None = None,
    ) -> tuple[Any, dict[str, Any]]:
        if not fields:
            raise ValidationError("The 'fields' list must not be empty.")
        gen = self._variant(seed, max_array_length, max_depth)
        obj: dict[str, Any] = {}
        for field in fields:
            name = str(field.get("name") or "")
            if not name:
                raise ValidationError("Each mock field requires a name.")
            obj[name] = gen._from_field(field, 0)
        return obj, gen._summary(obj)

    def generate_openapi(
        self,
        document: str,
        target_path: str,
        method: str | None,
        seed: int | None = None,
        max_array_length: int | None = None,
        max_depth: int | None = None,
    ) -> dict[str, Any]:
        gen = self._variant(seed, max_array_length, max_depth)
        try:
            doc = yaml.safe_load(document)
        except yaml.YAMLError as exc:
            raise ValidationError(f"OpenAPI document is not valid YAML/JSON: {exc}") from exc
        if not isinstance(doc, dict) or "paths" not in doc:
            raise ValidationError("Expected an OpenAPI document with a 'paths' object.")
        paths = doc.get("paths") or {}
        op_spec = paths.get(target_path)
        if op_spec is None:
            raise ValidationError(
                "Path {!r} not found. Available: {}".format(
                    target_path, ", ".join(sorted(paths))
                )
            )
        if isinstance(op_spec, dict):
            methods = [k for k in op_spec if k.lower() in _HTTP_METHODS]
            if method:
                method = method.lower()
                if method not in methods:
                    raise ValidationError(
                        "Method {!r} not found for path {!r}. Available: {}".format(
                            method.upper(),
                            target_path,
                            ", ".join(m.upper() for m in methods),
                        )
                    )
                op = op_spec[method]
            elif len(methods) == 1:
                method = methods[0]
                op = op_spec[method]
            else:
                raise ValidationError(
                    "Specify a method for path {!r}: {}".format(
                        target_path, ", ".join(m.upper() for m in methods)
                    )
                )
        else:
            method = method or "get"
            op = {"responses": {"200": {"description": "default", "content": {}}}}
            # A bare string path is an opaque non-OpenAPI doc; be permissive.

        op = dict(op or {})
        operation_id = op.get("operationId")
        # Locate the first 2xx success response.
        status_code, content_type, resp_schema = gen._pick_response(op)
        parsed_schema = None
        if resp_schema:
            parsed_schema, _ = gen.generate_schema(
                resp_schema, seed, max_array_length, max_depth
            )
        return {
            "valid": True,
            "error": None,
            "operation_id": operation_id,
            "path": target_path,
            "method": str(method).upper(),
            "status_code": status_code,
            "content_type": content_type,
            "content": parsed_schema,
            "json": json.dumps(parsed_schema, ensure_ascii=False, indent=2)
                    if parsed_schema is not None else None,
            "matched_schema": None,
        }

    def _pick_response(
        self, op: dict[str, Any]
    ) -> tuple[int | None, str | None, dict[str, Any] | None]:
        responses = op.get("responses") or {}
        ordered = sorted(
            responses.items(),
            key=lambda kv: (0 if str(kv[0]).startswith("2") else 1, str(kv[0])),
        )
        for raw_code, resp in ordered:
            code = str(raw_code)
            content = (resp or {}).get("content") or {}
            if code in ("default",) or code.startswith("2"):
                for ctype in ("application/json", "application/*+json", "*/*"):
                    if ctype in content:
                        schema = (content[ctype] or {}).get("schema")
                        if isinstance(schema, dict):
                            return _int_or_none(code), ctype, schema
                if content:
                    ctype, media = next(iter(content.items()))
                    schema = (media or {}).get("schema") or {}
                    return _int_or_none(code), ctype, (schema if isinstance(schema, dict) else None)
                if not content and code.startswith("2"):
                    return _int_or_none(code), None, None
        return None, None, None

    # ------------------------------------------------------------ schema walk

    def _from_schema(self, schema: Any, depth: int) -> Any:
        self._tick(depth)
        if not isinstance(schema, dict):
            return schema
        if "const" in schema:
            return schema["const"]
        if "enum" in schema and isinstance(schema["enum"], list) and schema["enum"]:
            return self._rng.choice(schema["enum"])
        if "default" in schema:
            return schema["default"]
        if "example" in schema:
            return schema["example"]

        for key in ("anyOf", "oneOf"):
            options = schema.get(key)
            if isinstance(options, list) and options:
                return self._from_schema(self._rng.choice(options), depth)

        if "type" not in schema:
            # Schema with properties but no type is an implicit object.
            if "properties" in schema:
                return self._from_object_schema(schema, depth)
            return None

        type_ = str(schema["type"])
        type_ = _TYPE_ALIASES.get(type_, type_)
        if type_ == "object":
            return self._from_object_schema(schema, depth)
        if type_ == "array":
            return self._from_array_schema(schema, depth)
        if type_ == "integer":
            return self._from_integer(schema)
        if type_ == "number":
            return self._from_number(schema)
        if type_ == "boolean":
            return self._rng.choice([True, False])
        if type_ == "null":
            return None
        # string
        return self._from_string(schema)

    def _from_object_schema(self, schema: dict[str, Any], depth: int) -> dict[str, Any]:
        result: dict[str, Any] = {}
        properties = schema.get("properties") or {}
        if not isinstance(properties, dict):
            return result
        for name, subschema in properties.items():
            if isinstance(subschema, dict) and subschema.get("nullable") is True:
                picks = [None, self._from_schema(subschema, depth + 1)]
                result[name] = self._rng.choice(picks)
            else:
                if isinstance(subschema, dict) and "type" not in subschema \
                        and "properties" not in subschema and "enum" not in subschema:
                    result[name] = None
                elif isinstance(subschema, dict) and "type" not in subschema \
                        and ("anyOf" in subschema or "oneOf" in subschema):
                    result[name] = self._from_schema(subschema, depth + 1)
                else:
                    result[name] = self._from_schema(subschema, depth + 1)
        return result

    def _from_array_schema(self, schema: dict[str, Any], depth: int) -> list[Any]:
        items = schema.get("items")
        min_items = int(schema.get("minItems", 0) or 0)
        max_items = int(schema.get("maxItems", self._max_array_length) or self._max_array_length)
        upper = max(min(min_items, self._max_array_length), min(max_items, self._max_array_length))
        lower = min(min_items, upper)
        count = self._rng.randint(lower, upper) if upper > lower else upper
        if count > self._max_array_length:
            count = self._max_array_length
            self._truncated = True
        if items is None:
            return [None for _ in range(count)]
        return [self._from_schema(items, depth + 1) for _ in range(count)]

    def _from_integer(self, schema: dict[str, Any]) -> int:
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if isinstance(minimum, int) and isinstance(maximum, int):
            return self._rng.randint(minimum, maximum)
        base = max(0, int(minimum) if minimum is not None else 0)
        top = min(_MAX_INT, int(maximum) if maximum is not None else base + 1000)
        if top < base:
            return base
        return self._rng.randint(base, top)

    def _from_number(self, schema: dict[str, Any]) -> float:
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if isinstance(minimum, (int, float)) and isinstance(maximum, (int, float)):
            return round(self._rng.uniform(minimum, maximum), 4)
        return round(self._rng.uniform(0, 1000), 4)

    def _from_string(self, schema: dict[str, Any]) -> str:
        fmt = schema.get("format")
        value = self._string_for_format(fmt)
        if value is None:
            if "pattern" in schema:
                return _pattern_sample(str(schema["pattern"]), self._rng)
            min_len = int(schema.get("minLength", 0) or 0)
            max_len = int(schema.get("maxLength", 32) or 32)
            if max_len < min_len:
                max_len = min_len
            length = self._rng.randint(min_len, max(1, min(64, max_len)))
            return self._random_string(length)
        return value

    def _string_for_format(self, fmt: Any) -> str | None:
        if not isinstance(fmt, str):
            return None
        f = fmt.lower()
        now = _dt.datetime.now(_dt.UTC)
        if f == "email":
            return f"{self._random_string(8).lower()}@example.com"
        if f == "uuid":
            return str(_uuid.uuid4())
        if f == "date":
            return now.date().isoformat()
        if f == "date-time":
            return now.isoformat(timespec="seconds")
        if f == "time":
            return now.strftime("%H:%M:%S")
        if f == "url" or f == "uri":
            return f"https://example.com/{self._random_string(6)}"
        if f == "hostname":
            return f"{self._random_string(6).lower()}.example.com"
        if f == "ipv4":
            return ".".join(str(self._rng.randint(1, 254)) for _ in range(4))
        if f == "ipv6":
            return ":".join(f"{self._rng.randint(0, 0xFFFF):x}" for _ in range(8))
        if f in ("username", "handle"):
            return f"user_{self._random_string(6).lower()}"
        if f in ("datetime", "timestamp"):
            return now.isoformat(timespec="seconds")
        if f in ("phone", "telephone"):
            return "+{}{}".format(self._rng.choice(["1", "44", "49", "358", "91"]),
                              "".join(str(self._rng.randint(0, 9)) for _ in range(9)))
        if f == "color":
            return f"#{self._rng.randint(0, 0xFFFFFF):06x}"
        if f in ("password", "token"):
            return self._random_string(16)
        if f in ("first_name", "givenName"):
            return self._rng.choice(_FIRST_NAMES)
        if f in ("last_name", "familyName"):
            return self._rng.choice(_LAST_NAMES)
        if f == "company":
            return self._rng.choice(_COMPANIES)
        if f == "name":
            return f"{self._rng.choice(_FIRST_NAMES)} {self._rng.choice(_LAST_NAMES)}"
        return None

    def _random_string(self, length: int) -> str:
        charset = string.ascii_letters + string.digits
        return "".join(self._rng.choice(charset) for _ in range(length))

    # -------------------------------------------------------------- fields DSL

    def _from_field(self, field: dict[str, Any], depth: int) -> Any:
        self._tick(depth)
        if field.get("default") is not None:
            return field["default"]
        type_ = str(field.get("type") or "string")
        type_ = _TYPE_ALIASES.get(type_, type_)
        if field.get("enum"):
            return self._rng.choice(field["enum"]) if field["enum"] else None
        if "minimum" in field and "maximum" in field:
            return self._rng.randint(int(field["minimum"]), int(field["maximum"]))
        if type_ == "integer":
            return self._from_integer(field)
        if type_ == "number":
            return self._from_number(field)
        if type_ == "boolean":
            return self._rng.choice([True, False])
        if type_ == "null":
            return None
        if type_ == "enum":
            values = field.get("values") or field.get("enum") or ["a", "b", "c"]
            return self._rng.choice(list(values))
        if type_ == "object":
            return {"mock": "object"}
        if type_ == "array":
            count = self._rng.randint(
                int(field.get("min_items", 0) or 0),
                max(1, int(field.get("max_items", 5) or 5)),
            )
            item_type = str(field.get("item_type") or "string")
            item_field = {"type": item_type, "format": field.get("item_format", "none")}
            if count > self._max_array_length:
                count = self._max_array_length
                self._truncated = True
            return [self._from_field(item_field, depth + 1) for _ in range(count)]
        if type_ in ("datetime", "date"):
            type_ = "string"
        value = self._string_for_format(field.get("format"))
        if value is not None:
            return value
        min_len = int(field.get("min_length", 0) or 0)
        max_len = int(field.get("max_length", 32) or 32)
        if max_len < min_len:
            max_len = min_len
        length = self._rng.randint(min_len, max(1, min(64, max_len)))
        return self._random_string(length)

    def _tick(self, depth: int) -> None:
        self._node_count += 1
        if self._node_count > _MAX_NODES:
            raise ValidationError("Generated mock exceeds the node budget.")
        if depth > _MAX_DEPTH:
            raise ValidationError("Schema nesting too deep.")

    # --------------------------------------------------------------- helpers

    def _summary(self, value: Any) -> dict[str, Any]:
        def count_nodes(v: Any) -> int:
            if isinstance(v, dict):
                return 1 + sum(count_nodes(x) for x in v.values())
            if isinstance(v, list):
                return 1 + sum(count_nodes(x) for x in v)
            return 1

        node_count = count_nodes(value)
        return {
            "node_count": node_count,
            "truncated": self._truncated,
        }


_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


def _int_or_none(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _pattern_sample(pattern: str, rng: random.Random) -> str:
    r"""Best-effort sample for simple regex patterns (character classes, \d, \w)."""
    result = ""
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern):
            nxt = pattern[i + 1]
            i += 2
            if nxt == "d":
                result += rng.choice(string.digits)
            elif nxt == "w":
                result += rng.choice(string.ascii_letters + string.digits + "_")
            elif nxt == "s":
                result += rng.choice([" ", "\t"])
            else:
                result += nxt
            continue
        if ch == "[":
            end = pattern.find("]", i)
            if end == -1:
                result += ch
                i += 1
                continue
            inner = pattern[i + 1:end]
            if inner.startswith("^"):
                inner = inner[1:]
            if inner:
                result += rng.choice(inner.replace("a-z", string.ascii_lowercase)
                                     .replace("A-Z", string.ascii_uppercase)
                                     .replace("0-9", string.digits))
            i = end + 1
            continue
        if ch in "{}+*?":
            i += 1
            continue
        result += ch
        i += 1
    return result + rng.choice(string.digits)


_FIRST_NAMES = [
    "Alice", "Bob", "Carol", "David", "Emma", "Frank", "Grace", "Henry",
    "Ivy", "Jack", "Kate", "Liam", "Mia", "Noah", "Olivia", "Peter",
]
_LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
    "Davis", "Taylor", "Anderson", "Moore", "Jackson", "Martin", "Lee",
]
_COMPANIES = [
    "Acme Corporation", "Globex", "Initech", "Umbrella Corp", "Stark Industries",
    "Wayne Enterprises", "Wonka Industries", "Northwind Traders",
]
