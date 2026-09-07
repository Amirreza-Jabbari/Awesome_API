"""Tests for the image processing service and its /api/v1/image endpoints."""

from __future__ import annotations

import importlib.util
import io
import zipfile
from collections.abc import Iterator

import pytest
from app.core.config import Settings
from app.core.exceptions import (
    ImageFeatureDisabledError,
    ImageFormatUnsupportedError,
    ResourceLimitError,
)
from app.services.image_service import ImageService
from fastapi.testclient import TestClient
from PIL import Image

from .test_api import _build_app


def _png(width: int = 32, height: int = 24) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (width, height), (30, 40, 200)).save(buf, format="PNG")
    return buf.getvalue()


def _heic() -> bytes:
    import pillow_heif

    pillow_heif.register_heif_opener()  # type: ignore[attr-defined]
    buf = io.BytesIO()
    Image.new("RGB", (8, 8), (10, 20, 30)).save(buf, format="HEIF")
    return buf.getvalue()


def _psd() -> bytes:
    from psd_tools import PSDImage

    psd = PSDImage.frompil(Image.new("RGB", (8, 8), (200, 30, 30)))
    buf = io.BytesIO()
    psd.save(buf)
    return buf.getvalue()


def _pdf() -> bytes:
    from fpdf import FPDF

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("helvetica", size=12)
    pdf.cell(0, 10, "Hello")
    return bytes(pdf.output())


def _reopen(data: bytes) -> Image.Image:
    return Image.open(io.BytesIO(data))


def _service() -> ImageService:
    return ImageService(
        Settings(app_env="test", cache_enabled=False, rate_limit_enabled=False)
    )


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(_build_app()) as test_client:
        yield test_client


# ── Service: conversion ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_convert_png_to_jpeg() -> None:
    service = _service()
    result = await service.convert(
        filename="photo.png", data=_png(), output_format="jpeg", quality=80
    )
    assert result.media_type == "image/jpeg"
    assert result.format == "jpeg"
    assert result.filename == "photo.jpg"
    assert result.width == 32 and result.height == 24
    assert result.bytes_written == len(result.content)
    assert _reopen(result.content).format == "JPEG"


@pytest.mark.asyncio
async def test_convert_png_to_pdf() -> None:
    service = _service()
    result = await service.convert(filename="photo.png", data=_png(), output_format="pdf")
    assert result.content.startswith(b"%PDF")
    assert result.media_type == "application/pdf"


@pytest.mark.asyncio
async def test_convert_png_to_pdf_with_preset() -> None:
    service = _service()
    result = await service.convert(
        filename="photo.png",
        data=_png(),
        output_format="pdf",
        pdf_preset="a4-landscape",
        pdf_margin_mm=5.0,
    )
    assert result.content.startswith(b"%PDF")


@pytest.mark.asyncio
async def test_convert_pdf_paginate_tall_image() -> None:
    service = _service()
    result = await service.convert(
        filename="poster.png",
        data=_png(50, 600),
        output_format="pdf",
        pdf_preset="a4-portrait",
        pdf_paginate=True,
        pdf_quality="small",
    )
    assert result.content.startswith(b"%PDF")
    from pypdfium2 import PdfDocument

    assert len(PdfDocument(result.content)) > 1


@pytest.mark.asyncio
async def test_convert_target_size_budget() -> None:
    service = _service()
    result = await service.convert(
        filename="photo.png",
        data=_png(240, 180),
        output_format="webp",
        target_size_kb=12,
    )
    assert result.format == "webp"
    assert len(result.content) <= 14 * 1024


@pytest.mark.asyncio
async def test_convert_downscales_to_width() -> None:
    service = _service()
    result = await service.convert(
        filename="photo.png", data=_png(120, 60), output_format="png", width=30
    )
    assert result.width == 30
    assert result.height == 15


@pytest.mark.asyncio
async def test_convert_heic_input() -> None:
    service = _service()
    result = await service.convert(filename="image.heic", data=_heic(), output_format="png")
    assert result.width == 8 and result.height == 8
    assert _reopen(result.content).format == "PNG"


@pytest.mark.asyncio
async def test_convert_psd_flatten() -> None:
    service = _service()
    result = await service.convert(filename="layer.psd", data=_psd(), output_format="png")
    assert result.width == 8 and result.height == 8
    assert _reopen(result.content).format == "PNG"


@pytest.mark.asyncio
async def test_convert_rejects_pdf_input() -> None:
    service = _service()
    with pytest.raises(ImageFormatUnsupportedError):
        await service.convert(filename="doc.pdf", data=_pdf(), output_format="png")


@pytest.mark.asyncio
async def test_convert_unsupported_output_format() -> None:
    service = _service()
    with pytest.raises(ImageFormatUnsupportedError):
        await service.convert(filename="photo.png", data=_png(), output_format="gif")


@pytest.mark.asyncio
async def test_convert_oversized_upload_rejected() -> None:
    service = _service()
    with pytest.raises(ResourceLimitError):
        await service.convert(
            filename="photo.png",
            data=b"\x00" * (service._settings.max_image_bytes + 1),
            output_format="png",
        )


# ── Service: resize ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_resize_width() -> None:
    service = _service()
    result = await service.resize(filename="photo.png", data=_png(120, 60), width=24)
    assert result.width == 24
    assert result.height == 12


@pytest.mark.asyncio
async def test_resize_canvas_fit() -> None:
    service = _service()
    result = await service.resize(
        filename="photo.png", data=_png(100, 50), canvas_width=40, canvas_height=40
    )
    assert result.width == 40 and result.height == 40
    reopened = _reopen(result.content)
    assert reopened.getpixel((2, 2)) == (255, 255, 255)
    assert reopened.getpixel((20, 20)) == (30, 40, 200)


@pytest.mark.asyncio
async def test_resize_width_too_large() -> None:
    service = _service()
    with pytest.raises(ResourceLimitError):
        await service.resize(filename="photo.png", data=_png(), width=25_000)


@pytest.mark.asyncio
async def test_resize_canvas_too_large() -> None:
    service = _service()
    with pytest.raises(ResourceLimitError):
        await service.resize(
            filename="photo.png", data=_png(), canvas_width=9_000, canvas_height=9_000
        )


# ── Service: PDF rasterization and background removal ───────────────────


@pytest.mark.asyncio
async def test_rasterize_pdf() -> None:
    service = _service()
    result = await service.rasterize_pdf(
        filename="doc.pdf", data=_pdf(), page_format="jpeg", dpi=72
    )
    assert result.format == "jpeg"
    assert result.item_count == 1
    assert zipfile.is_zipfile(io.BytesIO(result.content))
    with zipfile.ZipFile(io.BytesIO(result.content)) as archive:
        names = archive.namelist()
        assert len(names) == 1
        assert _reopen(archive.read(names[0])).format == "JPEG"


@pytest.mark.asyncio
async def test_background_removal_disabled() -> None:
    service = _service()
    with pytest.raises(ImageFeatureDisabledError):
        await service.remove_background(filename="photo.png", data=_png())


@pytest.mark.asyncio
async def test_capabilities() -> None:
    caps = _service().capabilities()
    assert ".png" in caps["read_formats"]
    assert "pdf" in caps["write_formats"]
    assert "a4-auto" in caps["pdf_presets"]
    assert caps["background_removal"]["enabled"] is False
    assert caps["background_removal"]["installed"] is (
        importlib.util.find_spec("rembg") is not None
    )


# ── Endpoints ───────────────────────────────────────────────────────────


def test_formats_endpoint(client: TestClient) -> None:
    r = client.get("/api/v1/image/formats")
    assert r.status_code == 200
    body = r.json()
    assert "pdf" in body["write_formats"]
    assert body["background_removal"]["enabled"] is False


def test_convert_endpoint_jpeg(client: TestClient) -> None:
    r = client.post(
        "/api/v1/image/convert",
        data={"format": "jpeg", "quality": "85"},
        files={"file": ("photo.png", _png(), "image/png")},
    )
    assert r.status_code == 200
    assert r.headers["Content-Type"] == "image/jpeg"
    assert "photo.jpg" in r.headers["Content-Disposition"]
    assert r.headers["X-Image-Format"] == "jpeg"
    assert int(r.headers["X-Image-Width"]) == 32
    assert int(r.headers["X-Image-Height"]) == 24
    assert int(r.headers["X-Image-Bytes"]) == len(r.content)
    assert _reopen(r.content).format == "JPEG"


def test_convert_endpoint_ico(client: TestClient) -> None:
    r = client.post(
        "/api/v1/image/convert",
        data={"format": "ico"},
        files={"file": ("photo.png", _png(), "image/png")},
    )
    assert r.status_code == 200
    assert r.headers["X-Image-Format"] == "ico"
    assert _reopen(r.content).format == "ICO"


def test_convert_endpoint_target_size(client: TestClient) -> None:
    r = client.post(
        "/api/v1/image/convert",
        data={"format": "webp", "target_size_kb": "10"},
        files={"file": ("photo.png", _png(200, 150), "image/png")},
    )
    assert r.status_code == 200
    assert r.headers["X-Image-Format"] == "webp"
    assert len(r.content) <= 12 * 1024


def test_convert_endpoint_validation_error(client: TestClient) -> None:
    r = client.post(
        "/api/v1/image/convert",
        data={"format": "jpeg", "quality": "0"},
        files={"file": ("photo.png", _png(), "image/png")},
    )
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "VALIDATION_ERROR"


def test_resize_endpoint_canvas(client: TestClient) -> None:
    r = client.post(
        "/api/v1/image/resize",
        data={"canvas_width": "40", "canvas_height": "40"},
        files={"file": ("photo.png", _png(32, 24), "image/png")},
    )
    assert r.status_code == 200
    assert int(r.headers["X-Image-Width"]) == 40
    assert int(r.headers["X-Image-Height"]) == 40


def test_resize_endpoint_requires_canvas_pair(client: TestClient) -> None:
    r = client.post(
        "/api/v1/image/resize",
        data={"canvas_width": "40"},
        files={"file": ("photo.png", _png(), "image/png")},
    )
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "IMAGE_PROCESSING_ERROR"


def test_rasterize_endpoint(client: TestClient) -> None:
    r = client.post(
        "/api/v1/image/rasterize",
        data={"page_format": "jpeg", "dpi": "72"},
        files={"file": ("doc.pdf", _pdf(), "application/pdf")},
    )
    assert r.status_code == 200
    assert r.headers["X-Image-Pages"] == "1"
    assert zipfile.is_zipfile(io.BytesIO(r.content))


def test_background_endpoint_disabled(client: TestClient) -> None:
    r = client.post(
        "/api/v1/image/background",
        data={"output_format": "png"},
        files={"file": ("photo.png", _png(), "image/png")},
    )
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "IMAGE_FEATURE_DISABLED"
