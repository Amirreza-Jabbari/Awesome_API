#!/usr/bin/env python3
"""Generate small dependency-light Python and TypeScript SDKs from OpenAPI.

The OpenAPI document produced by the running application is the only source of
truth. Generated files are disposable artifacts and are not hand-edited.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


def _operation_name(method: str, path: str, operation: dict[str, Any]) -> str:
    operation_id = operation.get("operationId")
    if isinstance(operation_id, str) and operation_id:
        return re.sub(r"[^A-Za-z0-9_]", "_", operation_id).strip("_")
    pieces = [method.lower(), *[p for p in path.strip("/").split("/") if p]]
    return "_".join(re.sub(r"[^A-Za-z0-9_]", "_", p) for p in pieces)


def load_openapi() -> dict[str, Any]:
    from app.main import app

    document = app.openapi()
    # Round-trip to ensure the generated artifact is JSON-serializable.
    return json.loads(json.dumps(document))


def generate_python(spec: dict[str, Any]) -> str:
    operations: list[tuple[str, str, dict[str, Any]]] = []
    for path, path_item in sorted(spec.get("paths", {}).items()):
        for method, operation in sorted(path_item.items()):
            if method.lower() in {"get", "post", "put", "patch", "delete", "head", "options"}:
                operations.append((method.upper(), path, operation))

    lines = [
        '"""Generated from Awesome_API OpenAPI; do not edit manually."""',
        "from __future__ import annotations",
        "",
        "import json",
        "from typing import Any",
        "from urllib.request import Request, urlopen",
        "",
        "class AwesomeAPIError(RuntimeError):",
        "    def __init__(self, status_code: int, payload: Any) -> None:",
        "        self.status_code = status_code",
        "        self.payload = payload",
        "        super().__init__(f\"Awesome_API request failed with HTTP {status_code}\")",
        "",
        "class AwesomeAPIClient:",
        "    def __init__(self, base_url: str, timeout: float = 10.0) -> None:",
        "        self.base_url = base_url.rstrip('/')",
        "        self.timeout = timeout",
        "",
        "    def request(self, method: str, path: str, body: Any = None) -> Any:",
        "        data = None if body is None else json.dumps(body).encode('utf-8')",
        "        headers = {'Accept': 'application/json'}",
        "        if data is not None:",
        "            headers['Content-Type'] = 'application/json'",
        "        request = Request(self.base_url + path, data=data, headers=headers, method=method)",
        "        try:",
        "            with urlopen(request, timeout=self.timeout) as response:",
        "                raw = response.read()",
        "                return json.loads(raw) if raw else None",
        "        except Exception as exc:",
        "            status = getattr(exc, 'code', 0)",
        "            payload = None",
        "            try:",
        "                raw = exc.read()  # type: ignore[attr-defined]",
        "                payload = json.loads(raw) if raw else None",
        "            except Exception:",
        "                payload = None",
        "            raise AwesomeAPIError(status, payload) from exc",
        "",
    ]
    for method, path, operation in operations:
        name = _operation_name(method, path, operation)
        lines += [
            f"    def {name}(self, body: Any = None) -> Any:",
            f"        return self.request({method!r}, {path!r}, body)",
            "",
        ]
    return "\n".join(lines).rstrip() + "\n"


def generate_typescript(spec: dict[str, Any]) -> str:
    operations: list[tuple[str, str, dict[str, Any]]] = []
    for path, path_item in sorted(spec.get("paths", {}).items()):
        for method, operation in sorted(path_item.items()):
            if method.lower() in {"get", "post", "put", "patch", "delete", "head", "options"}:
                operations.append((method.upper(), path, operation))

    lines = [
        "/** Generated from Awesome_API OpenAPI; do not edit manually. */",
        "export class AwesomeAPIError extends Error {",
        "  constructor(public status: number, public payload: unknown) {",
        "    super(`Awesome_API request failed with HTTP ${status}`);",
        "  }",
        "}",
        "",
        "export class AwesomeAPIClient {",
        "  constructor(private readonly baseUrl: string, private readonly timeoutMs = 10000) {}",
        "",
        "  async request(method: string, path: string, body?: unknown): Promise<unknown> {",
        "    const controller = new AbortController();",
        "    const timer = setTimeout(() => controller.abort(), this.timeoutMs);",
        "    try {",
        "      const response = await fetch(this.baseUrl.replace(/\\/$/, '') + path, {",
        "        method,",
        "        headers: body === undefined ? { Accept: 'application/json' } : { Accept: 'application/json', 'Content-Type': 'application/json' },",
        "        body: body === undefined ? undefined : JSON.stringify(body),",
        "        signal: controller.signal,",
        "      });",
        "      const payload = await response.json().catch(() => undefined);",
        "      if (!response.ok) throw new AwesomeAPIError(response.status, payload);",
        "      return payload;",
        "    } finally {",
        "      clearTimeout(timer);",
        "    }",
        "  }",
        "",
    ]
    for method, path, operation in operations:
        name = _operation_name(method, path, operation)
        lines += [
            f"  async {name}(body?: unknown): Promise<unknown> {{",
            f"    return this.request({method!r}, {path!r}, body);",
            "  }",
            "",
        ]
    lines += ["}", ""]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", default="sdk")
    args = parser.parse_args()
    out = Path(args.output_dir)
    (out / "python").mkdir(parents=True, exist_ok=True)
    (out / "typescript").mkdir(parents=True, exist_ok=True)

    spec = load_openapi()
    (out / "openapi.json").write_text(
        json.dumps(spec, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (out / "python" / "awesome_api_client.py").write_text(
        generate_python(spec), encoding="utf-8"
    )
    (out / "typescript" / "awesome-api-client.ts").write_text(
        generate_typescript(spec), encoding="utf-8"
    )
    print(f"Generated SDKs for {sum(len(v) for v in spec.get('paths', {}).values())} operations.")


if __name__ == "__main__":
    main()
