"""OpenAPI post-processing: consistent examples and documented error responses."""
from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from fastapi.routing import APIRoute, iter_route_contexts


def _resolve_schema(schema: dict[str, Any], components: dict[str, Any]) -> dict[str, Any]:
    ref = schema.get("$ref")
    if not isinstance(ref, str) or not ref.startswith("#/components/schemas/"):
        return schema
    name = ref.rsplit("/", 1)[-1]
    return components.get("schemas", {}).get(name, {}) if isinstance(components, dict) else {}


def _example(schema: dict[str, Any], components: dict[str, Any], name: str = "") -> Any:
    schema = _resolve_schema(schema, components)
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    if isinstance(schema.get("enum"), list) and schema["enum"]:
        return schema["enum"][0]
    if "oneOf" in schema and isinstance(schema["oneOf"], list) and schema["oneOf"]:
        return _example(schema["oneOf"][0], components, name)
    if "anyOf" in schema and isinstance(schema["anyOf"], list) and schema["anyOf"]:
        return _example(schema["anyOf"][0], components, name)

    lowered = name.lower()
    fmt = str(schema.get("format", "")).lower()
    if "password" in lowered:
        return "example-password-123!"
    if "secret" in lowered:
        return "correct-horse-battery-staple-with-extra-entropy"
    if lowered in {"token", "authorization"}:
        return "example-token"
    if lowered in {"url", "uri", "host", "hostname", "website"} or fmt in {"uri", "url"}:
        return "https://example.com"
    if "email" in lowered or fmt == "email":
        return "user@example.com"
    if lowered in {"domain", "target_path"}:
        return "example.com" if lowered == "domain" else "/example"
    if lowered == "ip":
        return "8.8.8.8"
    if lowered == "record_types":
        return ["A", "AAAA"]
    if lowered == "country":
        return "US"
    if lowered == "ulid":
        return "01ARZ3NDEKTSV4RRFFQ69G5FAV"
    if lowered in {"headers", "request_headers", "response_headers"}:
        if schema.get("type") == "object":
            return {"Content-Type": "application/json"}
        return "From: user@example.com\\nTo: user@example.com"
    if lowered in {"data"}:
        return "eA=="
    if lowered in {"input", "value", "document", "document_a", "document_b"}:
        return "{}"
    if lowered in {"pattern", "regex"}:
        return r"^example\.[a-z]+$"
    if lowered == "text":
        return "example text"

    typ = schema.get("type")
    if typ == "object" or "properties" in schema:
        props = schema.get("properties") or {}
        if not isinstance(props, dict):
            return {}
        required = set(schema.get("required") or [])
        result = {
            prop_name: _example(prop_schema, components, prop_name)
            for prop_name, prop_schema in props.items()
            if isinstance(prop_schema, dict) and prop_name in required
        }
        # These request models intentionally have no required fields because
        # validation is expressed as an exclusive-input invariant.
        if {"timestamp", "datetime"} <= set(props):
            result = {"timestamp": 1704067200}
        elif {"ip", "latitude", "longitude"} <= set(props):
            result = {"ip": "8.8.8.8"}
        elif {"schema", "fields"} <= set(props):
            result = {"fields": [{"name": "email", "type": "email"}]}
        return result
    if typ == "array":
        item = schema.get("items")
        return [_example(item, components, "item")] if isinstance(item, dict) else []
    if typ == "integer":
        return schema.get("minimum", 1)
    if typ == "number":
        return schema.get("minimum", 1)
    if typ == "boolean":
        return True
    return "example"


def customize_openapi(app: FastAPI) -> dict[str, Any]:
    if app.openapi_schema:
        return app.openapi_schema

    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
        tags=getattr(app, "openapi_tags", None),
    )
    components = schema.setdefault("components", {})
    schemas = components.setdefault("schemas", {})
    schemas.setdefault(
        "ErrorResponse",
        {
            "type": "object",
            "properties": {
                "error": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string"},
                        "message": {"type": "string"},
                        "details": {"type": "object"},
                        "request_id": {"type": "string"},
                    },
                    "required": ["code", "message", "request_id"],
                }
            },
            "required": ["error"],
        },
    )

    for route_context in iter_route_contexts(app.routes):
        route = route_context.original_route
        if not isinstance(route, APIRoute):
            continue
        for method in route.methods or set():
            operation_path = route_context.path_format or route.path
            operation = schema["paths"].get(operation_path, {}).get(method.lower())
            if not isinstance(operation, dict):
                continue

            request_body = operation.get("requestBody")
            if isinstance(request_body, dict):
                for media in (request_body.get("content") or {}).values():
                    if isinstance(media, dict) and isinstance(media.get("schema"), dict):
                        media.setdefault(
                            "examples",
                            {
                                "default": {
                                    "summary": "Representative request",
                                    "value": _example(
                                        media["schema"], components,
                                        getattr(route.body_field, "name", "") or "",
                                    ),
                                }
                            },
                        )

            if route.path == "/health" and "200" in operation.get("responses", {}):
                media = operation["responses"]["200"].setdefault("content", {}).setdefault(
                    "application/json", {}
                )
                media["examples"] = {
                    "default": {
                        "summary": "Healthy application",
                        "value": {"status": "healthy", "version": app.version},
                    }
                }
            elif route.path == "/ready" and "200" in operation.get("responses", {}):
                media = operation["responses"]["200"].setdefault("content", {}).setdefault(
                    "application/json", {}
                )
                media["examples"] = {
                    "default": {
                        "summary": "Ready application",
                        "value": {
                            "status": "ready",
                            "readiness": {"dns": True, "cache": True},
                            "diagnostics": {
                                "application": {"status": "healthy"},
                                "configuration": {"status": "healthy"},
                                "dns": {"status": "healthy"},
                                "cache": {"status": "healthy", "backend": "memory"},
                            },
                        },
                    }
                }
            elif route.path == "/version" and "200" in operation.get("responses", {}):
                media = operation["responses"]["200"].setdefault("content", {}).setdefault(
                    "application/json", {}
                )
                media["examples"] = {
                    "default": {
                        "summary": "Application version",
                        "value": {
                            "name": app.title,
                            "version": app.version,
                            "environment": "development",
                        },
                    }
                }

            responses = operation.setdefault("responses", {})
            for code, description in (
                ("429", "Rate limit exceeded."),
                ("500", "Unexpected internal error."),
            ):
                response = responses.setdefault(
                    code,
                    {
                        "description": description,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ErrorResponse"},
                                "examples": {
                                    "default": {
                                        "summary": "Standard error",
                                        "value": {
                                            "error": {
                                                "code": "RATE_LIMITED" if code == "429" else "INTERNAL_ERROR",
                                                "message": (
                                                    "Too many requests. Please try again later."
                                                    if code == "429"
                                                    else "An internal error occurred."
                                                ),
                                                "request_id": "01J00000000000000000000000",
                                            }
                                        },
                                    }
                                },
                            }
                        },
                    },
                )
                if isinstance(response, dict):
                    response.setdefault("content", {}).setdefault(
                        "application/json",
                        {"schema": {"$ref": "#/components/schemas/ErrorResponse"}},
                    )

            for code in ("200", "201"):
                response = responses.get(code)
                if not isinstance(response, dict):
                    continue
                for media in (response.get("content") or {}).values():
                    if isinstance(media, dict) and isinstance(media.get("schema"), dict):
                        media.setdefault(
                            "examples",
                            {
                                "default": {
                                    "summary": "Representative response",
                                    "value": _example(media["schema"], components),
                                }
                            },
                        )

    app.openapi_schema = schema
    return schema
