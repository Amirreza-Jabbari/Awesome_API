"""Pydantic response models for runtime design-system extraction."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, HttpUrl


class Evidence(BaseModel):
    value: str
    confidence: float = Field(ge=0, le=1)
    sources: list[str] = Field(default_factory=list)
    usage_count: int | None = Field(default=None, ge=0)


class ColorToken(Evidence):
    roles: list[str] = Field(default_factory=list)


class FontToken(BaseModel):
    family: str
    weights: list[int] = Field(default_factory=list)
    source: str
    confidence: float = Field(ge=0, le=1)


class SpacingScale(BaseModel):
    values: list[Evidence] = Field(default_factory=list)
    inferred_base_unit: float | None = None
    confidence: float = Field(ge=0, le=1)


class ComponentVariant(BaseModel):
    variant: str
    occurrences: int = Field(ge=1)
    style_signature: dict[str, str] = Field(default_factory=dict)
    confidence: float = Field(ge=0, le=1)


class ComponentInfo(BaseModel):
    detected: bool
    occurrences: int = Field(default=0, ge=0)
    variants: list[ComponentVariant] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)
    sources: list[str] = Field(default_factory=list)


class FrameworkHint(BaseModel):
    name: str
    confidence: float = Field(ge=0, le=1)
    sources: list[str] = Field(default_factory=list)


class BreakpointToken(Evidence):
    viewport_width: int | None = None


class LayoutInfo(BaseModel):
    container_max_widths: list[Evidence] = Field(default_factory=list)
    horizontal_paddings: list[Evidence] = Field(default_factory=list)
    common_gaps: list[Evidence] = Field(default_factory=list)
    grid_columns: list[Evidence] = Field(default_factory=list)


class IconInfo(BaseModel):
    type: str
    confidence: float = Field(ge=0, le=1)
    usage_count: int = Field(default=0, ge=0)
    sources: list[str] = Field(default_factory=list)


class WarningItem(BaseModel):
    code: str
    message: str


class DesignSystemTokens(BaseModel):
    colors: dict[str, ColorToken] = Field(default_factory=dict)
    typography: dict[str, Evidence] = Field(default_factory=dict)
    spacing: SpacingScale = Field(default_factory=SpacingScale)  # type: ignore[arg-type]
    radii: dict[str, Evidence] = Field(default_factory=dict)
    borders: dict[str, Evidence] = Field(default_factory=dict)
    shadows: dict[str, Evidence] = Field(default_factory=dict)
    breakpoints: dict[str, BreakpointToken] = Field(default_factory=dict)
    layout: LayoutInfo = Field(default_factory=LayoutInfo)
    components: dict[str, ComponentInfo] = Field(default_factory=dict)
    custom_properties: dict[str, Evidence] = Field(default_factory=dict)
    fonts: list[FontToken] = Field(default_factory=list)
    icons: list[IconInfo] = Field(default_factory=list)
    framework_hints: list[FrameworkHint] = Field(default_factory=list)


class DesignSystemAnalysis(BaseModel):
    duration_ms: int = Field(ge=0)
    browser: str = "chromium"
    viewport_count: int = Field(ge=0)
    resources_analyzed: int = Field(ge=0)
    bytes_downloaded: int = Field(ge=0)
    partial: bool


class DesignSystemResponse(BaseModel):
    url: HttpUrl
    final_url: HttpUrl
    fetched_at: datetime
    extractor_version: str
    schema_version: str
    analysis: DesignSystemAnalysis
    design_system: DesignSystemTokens
    warnings: list[WarningItem] = Field(default_factory=list)
