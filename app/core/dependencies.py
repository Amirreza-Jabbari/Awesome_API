"""Shared FastAPI dependencies.

Services, provider instances and caches are constructed once at application
startup and injected into endpoints via dedicated dependencies or directly
from the ``app.state`` application context. This keeps wiring in one place.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from fastapi import Request

from app.core.config import Settings, get_settings
from app.core.middleware import get_request_id


def get_settings_dep() -> Settings:
    return get_settings()


def get_request_id_dep() -> str | None:
    return get_request_id()


def get_dns_service(request: Request) -> Any:
    return request.app.state.dns_service


def get_mx_service(request: Request) -> Any:
    return request.app.state.mx_service


def get_disposable_email_service(request: Request) -> Any:
    return request.app.state.disposable_email_service


def get_email_service(request: Request) -> Any:
    return request.app.state.email_service


def get_password_service(request: Request) -> Any:
    return request.app.state.password_service


def get_user_agent_service(request: Request) -> Any:
    return request.app.state.user_agent_service


def get_phone_service(request: Request) -> Any:
    return request.app.state.phone_service


def get_url_service(request: Request) -> Any:
    return request.app.state.url_service


def get_webpage_service(request: Request) -> Any:
    return request.app.state.webpage_service


def get_whois_service(request: Request) -> Any:
    return request.app.state.whois_service


def get_domain_service(request: Request) -> Any:
    return request.app.state.domain_service


def get_ip_service(request: Request) -> Any:
    return request.app.state.ip_service


async def noop_lifespan_deps() -> AsyncIterator[None]:
    yield


def get_toolbox_service(request: Request) -> Any:
    return request.app.state.toolbox_service


def get_web_tools_service(request: Request) -> Any:
    return request.app.state.web_tools_service


def get_dns_tools_service(request: Request) -> Any:
    return request.app.state.dns_tools_service


def get_file_metadata_service(request: Request) -> Any:
    return request.app.state.file_metadata_service


def get_data_tools_service(request: Request) -> Any:
    return request.app.state.data_tools_service


def get_http_tools_service(request: Request) -> Any:
    return request.app.state.http_tools_service


def get_dev_tools_service(request: Request) -> Any:
    return request.app.state.dev_tools_service


def get_mock_data_service(request: Request) -> Any:
    return request.app.state.mock_data_service


def get_cron_service(request: Request) -> Any:
    return request.app.state.cron_service


def get_design_system_service(request: Request) -> Any:
    return request.app.state.design_system_service


def get_accessibility_audit_service(request: Request) -> Any:
    return request.app.state.accessibility_audit_service


def get_core_web_vitals_service(request: Request) -> Any:
    return request.app.state.core_web_vitals_service


def get_screenshot_service(request: Request) -> Any:
    return request.app.state.screenshot_service


def get_api_discovery_service(request: Request) -> Any:
    return request.app.state.api_discovery_service


def get_image_service(request: Request) -> Any:
    return request.app.state.image_service
