"""Schemas for the image-processing endpoints."""

from __future__ import annotations

from pydantic import BaseModel


class BackgroundRemovalInfo(BaseModel):
    enabled: bool
    installed: bool
    model: str


class ImageLimits(BaseModel):
    max_input_bytes: int
    max_pixels: int
    max_output_bytes: int
    max_pdf_pages: int
    max_pdf_dpi: int
    max_target_size_kb: int
    max_concurrent: int


class ImageFormatsResponse(BaseModel):
    """Capability inventory exposed by ``GET /api/v1/image/formats``."""

    read_formats: list[str]
    write_formats: list[str]
    pdf_presets: list[str]
    pdf_scale_modes: list[str]
    pdf_quality_presets: dict[str, int]
    background_removal: BackgroundRemovalInfo
    limits: ImageLimits
