"""Application configuration via environment variables.

All runtime settings are centralised here and bound from the environment
using pydantic-settings. Never import environment variables directly
elsewhere in the codebase.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Centralised application settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # Application
    app_name: str = "Awesome_API"
    app_env: Literal["development", "test", "production"] = "development"
    app_version: str = "1.0.0"
    debug: bool = False

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    cors_origins: str = ""

    # Logging
    log_level: str = "INFO"
    log_format: Literal["json", "text"] = "json"

    # DNS
    dns_nameservers: str = "1.1.1.1,1.0.0.1"
    dns_timeout: float = 3.0
    dns_lifetime: float = 5.0

    # Caching
    cache_enabled: bool = True
    cache_max_entries: int = 10_000
    redis_url: str = "redis://127.0.0.1:6379/0"
    dns_cache_ttl: int = 300
    whois_cache_ttl: int = 3600
    ip_lookup_cache_ttl: int = 3600
    design_system_cache_ttl: int = 900

    # Runtime Design System Extractor / Playwright
    design_system_enabled: bool = True
    design_system_browser_startup_timeout_ms: int = 15_000
    design_system_browser_timeout_ms: int = 8_000
    design_system_navigation_timeout_ms: int = 10_000
    design_system_render_wait_ms: int = 350
    design_system_queue_timeout_ms: int = 2_000
    design_system_max_redirects: int = 5
    design_system_max_requests: int = 80
    design_system_max_response_bytes: int = 3_000_000
    design_system_max_total_bytes: int = 15_000_000
    design_system_max_stylesheets: int = 30
    design_system_max_fonts: int = 30
    design_system_max_images: int = 30
    design_system_max_dom_nodes: int = 30_000
    design_system_max_css_rules: int = 5_000
    design_system_max_css_text: int = 32_000
    design_system_max_candidates: int = 600
    design_system_max_components: int = 50
    design_system_max_concurrent_browsers: int = 1
    design_system_max_concurrent_pages: int = 2
    design_system_viewports: list[dict[str, int]] = [
        {"width": 375, "height": 812},
        {"width": 768, "height": 1024},
        {"width": 1440, "height": 900},
    ]

    # Browser-based Web Intelligence APIs
    accessibility_audit_enabled: bool = True
    accessibility_audit_max_elements: int = 600
    web_vitals_enabled: bool = True
    web_vitals_measurement_ms: int = 500
    web_vitals_max_interactions: int = 5
    screenshot_enabled: bool = True
    screenshot_default_width: int = 1440
    screenshot_default_height: int = 900
    screenshot_max_width: int = 2560
    screenshot_max_height: int = 1600
    screenshot_max_bytes: int = 8_000_000
    screenshot_max_full_page_height: int = 10_000
    screenshot_timeout_ms: int = 10_000
    screenshot_max_concurrent: int = 2
    api_discovery_enabled: bool = True
    api_discovery_max_endpoints: int = 100
    api_discovery_max_probes: int = 6
    api_discovery_max_requests: int = 100
    api_discovery_well_known_paths: list[str] = [
        "/openapi.json", "/swagger.json", "/openapi.yaml", "/swagger.yaml",
        "/api-docs", "/docs",
    ]

    # Rate limiting
    rate_limit_enabled: bool = True
    rate_limit_requests: int = 60
    rate_limit_window_seconds: int = 60
    rate_limit_expensive_requests: int = 20
    rate_limit_network_requests: int = 15
    rate_limit_security_requests: int = 30
    rate_limit_max_keys: int = 100_000

    # Webpage metadata extraction
    webpage_timeout: float = 10.0
    webpage_connect_timeout: float = 5.0
    webpage_read_timeout: float = 8.0
    webpage_max_response_size: int = 5_242_880
    webpage_max_redirects: int = 5
    webpage_user_agent: str = "Awesome_API/1.0 (+https://example.com/bot)"

    # HTTP request builder / response inspector
    http_tools_timeout: float = 10.0
    http_tools_connect_timeout: float = 5.0
    http_tools_read_timeout: float = 8.0
    http_tools_max_response_size: int = 5_242_880
    http_tools_max_redirects: int = 5
    http_tools_max_headers: int = 60

    # Generic outbound HTTP timeout
    http_timeout: float = 10.0

    # Providers
    geoip_provider: Literal["none", "free", "ip-api", "maxmind"] = "free"
    # Optional MaxMind database path. The default "free" provider needs no key.
    geoip_api_key: str = ""

    whois_timeout: float = 10.0
    rdap_timeout: float = 10.0

    # Observability
    metrics_enabled: bool = False
    metrics_port: int = 9090

    # Request/resource limits
    max_request_body_bytes: int = 12_000_000
    max_json_body_bytes: int = 10_500_000
    max_url_length: int = 8_192
    max_response_body_bytes: int = 10_000_000
    max_json_depth: int = 100
    max_json_nodes: int = 100_000
    max_parser_nodes: int = 100_000
    max_image_bytes: int = 7_500_000
    max_image_pixels: int = 40_000_000
    max_upstream_response_bytes: int = 5_242_880

    # Image processing (conversion, resizing, PDF generation/rasterization)
    image_width_max: int = 24_000
    image_canvas_max_dimension: int = 8_192
    image_target_size_min_kb: int = 8
    image_target_size_max_kb: int = 4_000
    image_max_output_bytes: int = 15_000_000
    image_max_pdf_pages: int = 50
    image_max_pdf_dpi: int = 300
    image_max_rasterize_bytes: int = 40_000_000
    image_max_concurrent: int = 2
    image_timeout_seconds: float = 60.0
    image_background_removal_enabled: bool = False
    image_rembg_model: str = "u2net"

    # Provider keys
    provider_api_key: str = ""

    @model_validator(mode="after")
    def _validate_design_system(self) -> Settings:
        numeric = (
            self.design_system_browser_startup_timeout_ms,
            self.design_system_browser_timeout_ms,
            self.design_system_navigation_timeout_ms,
            self.design_system_render_wait_ms,
            self.design_system_queue_timeout_ms,
            self.design_system_max_redirects,
            self.design_system_max_requests,
            self.design_system_max_response_bytes,
            self.design_system_max_total_bytes,
            self.design_system_max_stylesheets,
            self.design_system_max_fonts,
            self.design_system_max_images,
            self.design_system_max_dom_nodes,
            self.design_system_max_css_rules,
            self.design_system_max_css_text,
            self.design_system_max_candidates,
            self.design_system_max_components,
            self.design_system_max_concurrent_browsers,
            self.design_system_max_concurrent_pages,
        )
        if any(value <= 0 for value in numeric):
            raise ValueError("Design System Extractor resource limits must be positive.")
        intelligence_numeric = (
            self.accessibility_audit_max_elements, self.web_vitals_measurement_ms,
            self.web_vitals_max_interactions, self.screenshot_default_width,
            self.screenshot_default_height, self.screenshot_max_width, self.screenshot_max_height,
            self.screenshot_max_bytes, self.screenshot_max_full_page_height,
            self.screenshot_timeout_ms, self.screenshot_max_concurrent,
            self.api_discovery_max_endpoints, self.api_discovery_max_probes,
            self.api_discovery_max_requests,
        )
        if any(v <= 0 for v in intelligence_numeric):
            raise ValueError("Browser intelligence limits must be positive.")
        if (self.screenshot_default_width > self.screenshot_max_width or
                self.screenshot_default_height > self.screenshot_max_height):
            raise ValueError("Default screenshot dimensions cannot exceed maximum dimensions.")
        if not self.api_discovery_well_known_paths:
            raise ValueError("API discovery probe paths cannot be empty.")
        if self.api_discovery_max_probes > len(self.api_discovery_well_known_paths):
            raise ValueError("API discovery probes cannot exceed the well-known path list.")

        if not 1 <= len(self.design_system_viewports) <= 3:
            raise ValueError("Design System Extractor supports one to three viewports.")
        for viewport in self.design_system_viewports:
            if viewport.get("width", 0) <= 0 or viewport.get("height", 0) <= 0:
                raise ValueError("Design System Extractor viewport dimensions must be positive.")
        return self

    @model_validator(mode="after")
    def _validate_image_processing(self) -> Settings:
        image_numeric = (
            self.image_width_max,
            self.image_canvas_max_dimension,
            self.image_target_size_min_kb,
            self.image_target_size_max_kb,
            self.image_max_output_bytes,
            self.image_max_pdf_pages,
            self.image_max_pdf_dpi,
            self.image_max_rasterize_bytes,
            self.image_max_concurrent,
        )
        if any(value <= 0 for value in image_numeric):
            raise ValueError("Image processing resource limits must be positive.")
        if self.image_timeout_seconds <= 0:
            raise ValueError("Image processing timeout must be positive.")
        if self.image_target_size_min_kb > self.image_target_size_max_kb:
            raise ValueError("Image target-size minimum cannot exceed the maximum.")
        if not 72 <= self.image_max_pdf_dpi <= 600:
            raise ValueError("Image PDF rendering DPI must be between 72 and 600.")
        if self.image_max_pdf_pages > 500:
            raise ValueError("Image PDF page cap is unreasonably high; keep it at most 500.")
        if not self.image_rembg_model.strip():
            raise ValueError("Image background-removal model name cannot be empty.")
        return self

    # ---- Derived helpers -------------------------------------------------

    @field_validator("dns_nameservers")
    @classmethod
    def _split_nameservers(cls, v: str) -> str:
        return ",".join(part.strip() for part in v.split(",") if part.strip())

    @property
    def dns_nameserver_list(self) -> list[str]:
        return [part.strip() for part in self.dns_nameservers.split(",") if part.strip()]

    @property
    def cors_origin_list(self) -> list[str]:
        return [part.strip() for part in self.cors_origins.split(",") if part.strip()]

    @property
    def is_dev(self) -> bool:
        return self.app_env == "development"


@lru_cache
def get_settings() -> Settings:
    """Return the cached Settings singleton."""
    return Settings()


def reload_settings() -> Settings:
    """Force-reload settings (used mainly in tests)."""
    get_settings.cache_clear()
    return get_settings()
