"""Structured logging setup.

Logs are emitted as JSON objects by default so they can be parsed by common
log aggregators. A ``request_id`` is attached to every request via contextvars
in the request middleware.

Sensitive data (passwords, API keys, tokens, full request bodies) must never
be logged. Endpoints that receive potentially sensitive bodies are responsible
for logging only their safe/derived fields.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

from app.core.config import Settings


class JsonFormatter(logging.Formatter):
    """Render log records as a single-line JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in (
            "request_id",
            "method",
            "path",
            "status_code",
            "duration_ms",
            "provider",
            "operation",
            "success",
            "cache_hit",
        ):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        if (
            record.exc_info
            and record.exc_info[0] is not None
            and getattr(record, "include_traceback", False)
        ):
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class RequestContextFilter(logging.Filter):
    """Attach the validated request ID to every log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            from app.core.middleware import get_request_id
            request_id = get_request_id()
        except Exception:
            request_id = None
        if request_id:
            record.request_id = request_id
        return True


class SensitiveDataFilter(logging.Filter):
    """Redact common credential patterns from messages as a defensive layer."""

    _SENSITIVE = (
        "api_key",
        "apikey",
        "authorization",
        "token",
        "password",
        "secret",
    )

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        lowered = msg.lower()
        for key in self._SENSITIVE:
            if key in lowered:
                record.msg = "[REDACTED]"
                record.args = ()
        if hasattr(record, "request_id"):
            # keep request_id attribute safe
            pass
        return True


def configure_logging(settings: Settings) -> None:
    """Configure the root logger based on settings."""
    root = logging.getLogger()
    # Remove existing handlers to avoid duplicates on reload.
    for handler in list(root.handlers):
        root.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    if settings.log_format == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)s %(name)s [%(request_id)s] %(message)s"
            )
        )
    handler.addFilter(RequestContextFilter())
    handler.addFilter(SensitiveDataFilter())

    root.setLevel(settings.log_level.upper())
    root.addHandler(handler)

    # Tame noisy third-party loggers.
    for name in ("httpx", "httpcore"):
        logging.getLogger(name).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Return a logger bound to a module name."""
    return logging.getLogger(name)
