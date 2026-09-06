"""Schemas for browser-based web intelligence APIs."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, HttpUrl


class BrowserAnalysisMeta(BaseModel):
    duration_ms: int = Field(ge=0)
    browser: str = "chromium"
    partial: bool = False
    resources_analyzed: int = Field(ge=0)
    bytes_downloaded: int = Field(ge=0)


class AuditWCAG(BaseModel):
    criterion: str
    level: Literal["A", "AA", "AAA", "unknown"]
    name: str


class AccessibilityIssue(BaseModel):
    element: str
    selector: str | None = None
    issue: str
    severity: Literal["error", "warning", "notice"]
    message: str
    wcag: list[AuditWCAG] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)


class AccessibilitySummary(BaseModel):
    errors: int = Field(ge=0)
    warnings: int = Field(ge=0)
    notices: int = Field(ge=0)
    passed: int = Field(ge=0)


class AccessibilityResponse(BaseModel):
    url: HttpUrl
    final_url: HttpUrl
    fetched_at: datetime
    analysis: BrowserAnalysisMeta
    viewport: dict[str, int]
    elements_analyzed: int = Field(ge=0)
    summary: AccessibilitySummary
    issues: list[AccessibilityIssue] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class MetricValue(BaseModel):
    value_ms: float | None = Field(default=None, ge=0)
    value: float | None = Field(default=None, ge=0)
    status: Literal["good", "needs_improvement", "poor", "not_available", "estimated"]
    source: Literal["browser", "synthetic", "unavailable"]
    reason: str | None = None


class PerformanceBottleneck(BaseModel):
    type: str
    severity: Literal["warning", "notice"]
    details: str


class WebVitalsViewport(BaseModel):
    viewport: dict[str, int]
    fcp: MetricValue
    lcp: MetricValue
    cls: MetricValue
    inp: MetricValue
    ttfb: MetricValue
    dom_content_loaded_ms: float | None = Field(default=None, ge=0)
    load_event_ms: float | None = Field(default=None, ge=0)
    resource_count: int = Field(ge=0)
    transfer_bytes: int = Field(ge=0)
    js_transfer_bytes: int = Field(ge=0)
    css_transfer_bytes: int = Field(ge=0)
    image_transfer_bytes: int = Field(ge=0)
    long_tasks: int = Field(ge=0)
    total_blocking_time_ms: float = Field(ge=0)
    bottlenecks: list[PerformanceBottleneck] = Field(default_factory=list)


class WebVitalsResponse(BaseModel):
    url: HttpUrl
    final_url: HttpUrl
    fetched_at: datetime
    analysis: BrowserAnalysisMeta
    measurement_duration_ms: int = Field(ge=0)
    synthetic: bool = True
    viewports: list[WebVitalsViewport] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ScreenshotResponseMeta(BaseModel):
    url: HttpUrl
    final_url: HttpUrl
    fetched_at: datetime
    width: int = Field(ge=1)
    height: int = Field(ge=1)
    format: Literal["png", "jpeg", "webp"]
    bytes: int = Field(ge=0)
    full_page: bool
    selector: str | None = None
    partial: bool = False


class DiscoveredEndpoint(BaseModel):
    url: HttpUrl
    method: str
    type: Literal["openapi", "graphql", "json_api", "rest", "websocket", "form"]
    origin_type: Literal["first_party", "third_party"]
    content_type: str | None = None
    status: int | None = Field(default=None, ge=100, le=599)
    source: Literal["browser_network", "document", "script", "well_known", "form"]
    confidence: float = Field(ge=0, le=1)


class DiscoveryResponse(BaseModel):
    url: HttpUrl
    final_url: HttpUrl
    fetched_at: datetime
    analysis: BrowserAnalysisMeta
    requests_observed: int = Field(ge=0)
    endpoints_discovered: int = Field(ge=0)
    openapi_documents: int = Field(ge=0)
    graphql_endpoints: int = Field(ge=0)
    websockets: int = Field(ge=0)
    endpoints: list[DiscoveredEndpoint] = Field(default_factory=list)
    partial: bool = False
    warnings: list[str] = Field(default_factory=list)
