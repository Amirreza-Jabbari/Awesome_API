"""Centralized request/resource limits and bounded JSON helpers."""
from __future__ import annotations

import json
from typing import Any

from app.core.exceptions import ResourceLimitError, ValidationError


def validate_json_structure(value: Any, *, max_depth: int, max_nodes: int) -> None:
    """Validate depth/node budgets iteratively to avoid recursive walkers."""
    stack: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes:
            raise ResourceLimitError("JSON document exceeds the node limit.")
        if depth > max_depth:
            raise ResourceLimitError("JSON document is too deeply nested.")
        if isinstance(current, dict):
            stack.extend((v, depth + 1) for v in current.values())
        elif isinstance(current, list):
            stack.extend((v, depth + 1) for v in current)


def load_json_limited(
    text: str,
    *,
    max_depth: int,
    max_nodes: int,
    error_message: str = "Invalid JSON input.",
) -> Any:
    try:
        value = json.loads(text, parse_constant=lambda _: (_ for _ in ()).throw(
            ValueError("NaN/Infinity is not valid JSON")
        ))
    except RecursionError as exc:
        raise ResourceLimitError("JSON document is too deeply nested.") from exc
    except json.JSONDecodeError as exc:
        raise ValidationError(f"{error_message} {exc.msg}") from exc
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc
    validate_json_structure(value, max_depth=max_depth, max_nodes=max_nodes)
    return value


def validate_header_map(
    headers: dict[str, str], *, max_headers: int, max_name_length: int, max_value_length: int
) -> None:
    if len(headers) > max_headers:
        raise ResourceLimitError("Too many HTTP headers.")
    total = 0
    for name, value in headers.items():
        if len(name) > max_name_length or len(value) > max_value_length:
            raise ResourceLimitError("HTTP header exceeds the allowed size.")
        total += len(name) + len(value)
    if total > max_headers * (max_name_length + max_value_length):
        raise ResourceLimitError("HTTP headers exceed the aggregate size limit.")
