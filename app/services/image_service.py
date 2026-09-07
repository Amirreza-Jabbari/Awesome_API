"""Local image processing: conversion, resizing, PDF and background removal.

Image conversion/resizing/PDF capabilities (inspired by common image-compression
tools) implemented natively on Awesome_API infrastructure. Design rules:

* Everything runs fully in-memory; inputs are bounded by the request middleware
  and an explicit pixel/byte budget, so uploaded pixels can never exhaust RAM.
* CPU-bound Pillow/PDF work runs in a worker thread through ``asyncio.to_thread``
  with a hard timeout, and a semaphore caps concurrent decoding so a flood of
  large uploads cannot saturate cores.
* Outputs are re-encoded and never carry EXIF/location metadata.
* Unsupported or disabled features surface as typed exceptions handled by the
  shared exception envelope.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib.util
import io
import math
import os
import re
import tempfile
import time
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal, TypeVar

from PIL import Image, ImageOps

from app.core.config import Settings
from app.core.exceptions import (
    ImageFeatureDisabledError,
    ImageFormatUnsupportedError,
    ImageProcessingError,
    ImageTimeoutError,
    ResourceLimitError,
)
from app.core.logging import get_logger

logger = get_logger(__name__)

R = TypeVar("R")

OutputFormat = Literal[
    "jpeg", "jpg", "png", "webp", "avif", "ico", "tiff", "tif", "bmp", "pdf"
]

# Normalized output format -> (Pillow format, media type).
_OUTPUT_FORMATS: dict[str, tuple[str, str]] = {
    "jpeg": ("JPEG", "image/jpeg"),
    "jpg": ("JPEG", "image/jpeg"),
    "png": ("PNG", "image/png"),
    "webp": ("WEBP", "image/webp"),
    "avif": ("AVIF", "image/avif"),
    "ico": ("ICO", "image/x-icon"),
    "tiff": ("TIFF", "image/tiff"),
    "tif": ("TIFF", "image/tiff"),
    "bmp": ("BMP", "image/bmp"),
    "pdf": ("PDF", "application/pdf"),
}

_RASTERIZE_FORMATS: dict[str, tuple[str, str]] = {
    "jpeg": ("JPEG", "image/jpeg"),
    "jpg": ("JPEG", "image/jpeg"),
    "png": ("PNG", "image/png"),
}

_PDF_SCALE_MODES = {"fit", "fill"}

_PDF_PRESETS: dict[str, dict[str, Any]] = {
    "original": {"size": None, "margin_mm": 0.0, "auto_rotate": False},
    "a4-auto": {"size": (595, 842), "margin_mm": 10.0, "auto_rotate": True},
    "a4-portrait": {"size": (595, 842), "margin_mm": 10.0, "auto_rotate": False},
    "a4-landscape": {"size": (842, 595), "margin_mm": 10.0, "auto_rotate": False},
    "letter-auto": {"size": (612, 792), "margin_mm": 10.0, "auto_rotate": True},
    "letter-portrait": {"size": (612, 792), "margin_mm": 10.0, "auto_rotate": False},
    "letter-landscape": {"size": (792, 612), "margin_mm": 10.0, "auto_rotate": False},
    "mobile-portrait": {"size": (1080, 1920), "margin_mm": 0.0, "auto_rotate": False},
    "mobile-landscape": {"size": (1920, 1080), "margin_mm": 0.0, "auto_rotate": False},
}

_PDF_QUALITY: dict[str, dict[str, int | None]] = {
    "small": {"dpi": 96, "jpeg_quality": 55, "original_max_dimension": 1600},
    "medium": {"dpi": 150, "jpeg_quality": 70, "original_max_dimension": 2400},
    "high": {"dpi": 220, "jpeg_quality": 82, "original_max_dimension": 3600},
    "ultra": {"dpi": 300, "jpeg_quality": 92, "original_max_dimension": None},
}

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


@dataclass(frozen=True)
class ImageResult:
    """A single processed image or PDF document held in memory."""

    content: bytes
    media_type: str
    filename: str
    format: str
    width: int
    height: int
    bytes_written: int


@dataclass(frozen=True)
class ArchiveResult:
    """A ZIP archive of multiple generated files (e.g. rasterized PDF pages)."""

    content: bytes
    media_type: str
    filename: str
    item_count: int
    format: str


class ImageService:
    """In-memory image conversion/resizing service with hard resource limits."""

    def __init__(self, settings: Settings, metrics: Any | None = None) -> None:
        self._settings = settings
        self._metrics = metrics
        self._semaphore = asyncio.Semaphore(settings.image_max_concurrent)
        self._bg_session: Any | None = None
        Image.MAX_IMAGE_PIXELS = settings.max_image_pixels
        self._register_heif()

    # ── Public async API ────────────────────────────────────────────────────

    async def convert(
        self,
        *,
        filename: str,
        data: bytes,
        output_format: str,
        quality: int = 85,
        width: int | None = None,
        target_size_kb: int | None = None,
        pdf_preset: str | None = None,
        pdf_scale: str = "fit",
        pdf_margin_mm: float | None = None,
        pdf_paginate: bool = False,
        pdf_quality: str = "high",
    ) -> ImageResult:
        """Convert a single image (or PSD) to another raster format or PDF."""
        return await self._run(
            "convert",
            self._convert_impl,
            filename,
            data,
            output_format,
            quality,
            width,
            target_size_kb,
            pdf_preset,
            pdf_scale,
            pdf_margin_mm,
            pdf_paginate,
            pdf_quality,
        )

    async def resize(
        self,
        *,
        filename: str,
        data: bytes,
        width: int | None = None,
        canvas_width: int | None = None,
        canvas_height: int | None = None,
        mode: str = "fit",
        margin_mm: float = 0.0,
        auto_rotate: bool = False,
        output_format: str = "png",
    ) -> ImageResult:
        """Resize by width and/or fit an image onto a canvas box."""
        return await self._run(
            "resize",
            self._resize_impl,
            filename,
            data,
            width,
            canvas_width,
            canvas_height,
            mode,
            margin_mm,
            auto_rotate,
            output_format,
        )

    async def rasterize_pdf(
        self,
        *,
        filename: str,
        data: bytes,
        page_format: str = "jpeg",
        dpi: int = 150,
    ) -> ArchiveResult:
        """Rasterize a PDF into a ZIP of per-page images."""
        return await self._run(
            "rasterize", self._rasterize_impl, filename, data, page_format, dpi
        )

    async def remove_background(
        self, *, filename: str, data: bytes, output_format: str = "png"
    ) -> ImageResult:
        """Remove the background of an image via the optional rembg runtime."""
        return await self._run(
            "background_removal",
            self._remove_background_impl,
            filename,
            data,
            output_format,
        )

    # ── Capabilities ────────────────────────────────────────────────────────

    def capabilities(self) -> dict[str, Any]:
        """Describe what this deployment can read/write (for /image/formats)."""
        read_formats = sorted("." + ext.lower() for ext in Image.OPEN)
        if importlib.util.find_spec("pillow_heif") is not None:
            read_formats.extend([".heic", ".heif"])
        read_formats.extend([".pdf", ".psd"])
        write_formats: list[str] = []
        for key, (pil_fmt, _) in sorted(_OUTPUT_FORMATS.items()):
            if key in {"jpg", "tif"}:
                continue
            if pil_fmt == "PDF":
                write_formats.append("pdf")
            elif pil_fmt in getattr(Image, "SAVE", {}):
                write_formats.append(key)
        return {
            "read_formats": sorted(set(read_formats)),
            "write_formats": write_formats,
            "pdf_presets": list(_PDF_PRESETS),
            "pdf_scale_modes": sorted(_PDF_SCALE_MODES),
            "pdf_quality_presets": {k: v["dpi"] for k, v in _PDF_QUALITY.items()},
            "background_removal": {
                "enabled": self._settings.image_background_removal_enabled,
                "installed": importlib.util.find_spec("rembg") is not None,
                "model": self._settings.image_rembg_model,
            },
            "limits": {
                "max_input_bytes": self._settings.max_image_bytes,
                "max_pixels": self._settings.max_image_pixels,
                "max_output_bytes": self._settings.image_max_output_bytes,
                "max_pdf_pages": self._settings.image_max_pdf_pages,
                "max_pdf_dpi": self._settings.image_max_pdf_dpi,
                "max_target_size_kb": self._settings.image_target_size_max_kb,
                "max_concurrent": self._settings.image_max_concurrent,
            },
        }

    # ── Async plumbing ──────────────────────────────────────────────────────

    async def _run(self, operation: str, func: Callable[..., R], *args: Any) -> R:
        async with self._semaphore:
            start = time.perf_counter()
            try:
                result = await asyncio.wait_for(
                    asyncio.to_thread(func, *args),
                    timeout=self._settings.image_timeout_seconds,
                )
                self._observe(operation, start, True)
                return result
            except TimeoutError:
                logger.warning("image_operation_timeout op=%s", operation)
                self._observe(operation, start, False)
                raise ImageTimeoutError() from None
            except ResourceLimitError:
                self._observe(operation, start, False)
                raise
            except ImageFeatureDisabledError:
                self._observe(operation, start, False)
                raise
            except ImageFormatUnsupportedError:
                self._observe(operation, start, False)
                raise
            except (OSError, ValueError) as exc:
                logger.warning("image_operation_failed op=%s error=%s", operation, exc)
                self._observe(operation, start, False)
                raise ImageProcessingError() from exc

    def _observe(self, operation: str, start: float, success: bool) -> None:
        if self._metrics is not None:
            duration_ms = (time.perf_counter() - start) * 1000
            self._metrics.observe_provider("image", operation, duration_ms, success)

    # ── Conversion implementations (run in worker threads) ──────────────────

    def _convert_impl(
        self,
        filename: str,
        data: bytes,
        output_format: str,
        quality: int,
        width: int | None,
        target_size_kb: int | None,
        pdf_preset: str | None,
        pdf_scale: str,
        pdf_margin_mm: float | None,
        pdf_paginate: bool,
        pdf_quality: str,
    ) -> ImageResult:
        self._validate_input_size(data)
        if self._is_extension(filename, "pdf"):
            raise ImageFormatUnsupportedError(
                "PDF inputs are supported by /image/rasterize, not /image/convert."
            )

        format_key = output_format.strip().lower().lstrip(".")
        if format_key not in _OUTPUT_FORMATS:
            allowed = ", ".join(sorted({k for k in _OUTPUT_FORMATS} - {"jpg", "tif"}))
            raise ImageFormatUnsupportedError(
                f"Unsupported output format. Choose one of: {allowed}."
            )
        pil_fmt, media_type = _OUTPUT_FORMATS[format_key]

        img = self._load_source(filename, data)
        base_width, base_height = img.size

        if pil_fmt == "PDF":
            output = self._make_pdf(
                img,
                pdf_preset=pdf_preset,
                pdf_scale=pdf_scale,
                pdf_margin_mm=pdf_margin_mm,
                pdf_paginate=pdf_paginate,
                pdf_quality=pdf_quality,
            )
            return ImageResult(
                content=output,
                media_type=media_type,
                filename=self._output_filename(filename, ".pdf", page=None),
                format=format_key,
                width=base_width,
                height=base_height,
                bytes_written=len(output),
            )

        image = img.copy()
        if width is not None and width > 0:
            image = self._resize_width(image, width)

        if target_size_kb is not None and pil_fmt in {"JPEG", "WEBP", "AVIF"}:
            quality, output_bytes = self._encode_under_target(
                image, pil_fmt, target_size_kb
            )
        else:
            output_bytes = self._encode(image, pil_fmt, quality)

        return ImageResult(
            content=output_bytes,
            media_type=media_type,
            filename=self._output_filename(filename, self._extension_for(pil_fmt), page=None),
            format=format_key,
            width=image.width,
            height=image.height,
            bytes_written=len(output_bytes),
        )

    def _resize_impl(
        self,
        filename: str,
        data: bytes,
        width: int | None,
        canvas_width: int | None,
        canvas_height: int | None,
        mode: str,
        margin_mm: float,
        auto_rotate: bool,
        output_format: str,
    ) -> ImageResult:
        self._validate_input_size(data)
        format_key = output_format.strip().lower().lstrip(".")
        if format_key not in _OUTPUT_FORMATS or format_key == "pdf":
            allowed = ", ".join(sorted({k for k in _OUTPUT_FORMATS} - {"jpg", "tif", "pdf"}))
            raise ImageFormatUnsupportedError(
                f"Unsupported output format. Choose one of: {allowed}."
            )
        pil_fmt, media_type = _OUTPUT_FORMATS[format_key]
        if width is not None and canvas_width is None and width > self._settings.image_width_max:
            raise ResourceLimitError("Requested width exceeds the allowed maximum.")
        image = self._load_source(filename, data)
        if width is not None and width > 0:
            image = self._resize_width(image, width)
        if canvas_width is not None and canvas_height is not None:
            image = self._resize_to_canvas(
                image, canvas_width, canvas_height, mode, margin_mm, auto_rotate
            )
        output_bytes = self._encode(image, pil_fmt, 85)
        return ImageResult(
            content=output_bytes,
            media_type=media_type,
            filename=self._output_filename(filename, self._extension_for(pil_fmt), page=None),
            format=format_key,
            width=image.width,
            height=image.height,
            bytes_written=len(output_bytes),
        )

    def _rasterize_impl(
        self, filename: str, data: bytes, page_format: str, dpi: int
    ) -> ArchiveResult:
        self._validate_input_size(data)
        format_key = page_format.strip().lower().lstrip(".")
        if format_key not in _RASTERIZE_FORMATS:
            raise ImageFormatUnsupportedError(
                "Unsupported rasterized page format. Choose one of: jpeg, png."
            )
        pil_fmt, _ = _RASTERIZE_FORMATS[format_key]
        if not self._is_extension(filename, "pdf"):
            raise ImageFormatUnsupportedError("Rasterization requires a PDF input.")

        import pypdfium2 as pdfium

        page_dpi = max(36, min(dpi, self._settings.image_max_pdf_dpi))
        scale = page_dpi / 72.0
        stem = self._safe_stem(filename)

        try:
            document = pdfium.PdfDocument(data)
        except Exception as exc:
            logger.warning("pdf_parse_failed error=%s", exc)
            raise ImageFormatUnsupportedError(
                "The supplied file could not be parsed as PDF."
            ) from exc

        try:
            page_count = len(document)
            if page_count == 0:
                raise ImageFormatUnsupportedError("The PDF contains no renderable pages.")
            if page_count > self._settings.image_max_pdf_pages:
                raise ResourceLimitError("The PDF contains more pages than the allowed limit.")

            entries: list[tuple[str, bytes]] = []
            total_bytes = 0
            for index in range(page_count):
                page = document[index]
                try:
                    pil_page = page.render(scale=scale).to_pil()
                finally:
                    page.close()
                page_bytes = self._encode(pil_page, pil_fmt, 85)
                total_bytes += len(page_bytes)
                if total_bytes > self._settings.image_max_rasterize_bytes:
                    raise ResourceLimitError("Rasterized output exceeds the allowed total size.")
                name = f"{stem}_page-{index + 1}{self._extension_for(pil_fmt)}"
                entries.append((name, page_bytes))

            archive = io.BytesIO()
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                for name, content in entries:
                    zf.writestr(name, content)
            archive_bytes = archive.getvalue()
        finally:
            document.close()

        if len(archive_bytes) > self._settings.image_max_output_bytes:
            raise ResourceLimitError("Archive exceeds the allowed output size.")
        return ArchiveResult(
            content=archive_bytes,
            media_type="application/zip",
            filename=self._output_filename(filename, ".zip", page=None),
            item_count=len(entries),
            format=format_key,
        )

    def _remove_background_impl(
        self, filename: str, data: bytes, output_format: str
    ) -> ImageResult:
        del filename
        format_key = output_format.strip().lower().lstrip(".")
        if format_key not in {"png", "avif"}:
            raise ImageFormatUnsupportedError("Background removal outputs PNG or AVIF only.")
        if not self._settings.image_background_removal_enabled:
            raise ImageFeatureDisabledError(
                "Background removal is disabled on this deployment "
                "(IMAGE_BACKGROUND_REMOVAL_ENABLED must be true and the "
                "[image-ai] extra installed)."
            )
        try:
            from rembg import new_session, remove
        except ImportError as exc:
            raise ImageFeatureDisabledError(
                "Background removal is not installed on this deployment."
            ) from exc

        self._validate_input_size(data)
        self._load_image(data)

        if (
            self._bg_session is None
            or self._bg_session.model_name != self._settings.image_rembg_model
        ):
            self._bg_session = new_session(self._settings.image_rembg_model)
        try:
            with io.BytesIO(data) as stream:
                output = remove(stream.read(), session=self._bg_session, post_process_mask=True)
        except TypeError:
            output = remove(data, session=self._bg_session)

        output_img = self._load_image(output)
        if format_key == "avif":
            if output_img.mode not in ("RGB", "RGBA"):
                output_img = output_img.convert("RGBA")
            buf = io.BytesIO()
            output_img.save(buf, format="AVIF", quality=90)
            output = buf.getvalue()
        else:
            buf = io.BytesIO()
            output_img.save(buf, format="PNG")
            output = buf.getvalue()
        if len(output) > self._settings.image_max_output_bytes:
            raise ResourceLimitError("Background-removed image exceeds the allowed output size.")
        return ImageResult(
            content=output,
            media_type="image/avif" if format_key == "avif" else "image/png",
            filename=self._output_filename(
                "image", ".avif" if format_key == "avif" else ".png", page=None
            ),
            format=format_key,
            width=output_img.width,
            height=output_img.height,
            bytes_written=len(output),
        )

    # ── Shared building blocks ──────────────────────────────────────────────

    def _validate_input_size(self, data: bytes) -> None:
        if len(data) > self._settings.max_image_bytes:
            raise ResourceLimitError("Image exceeds the allowed upload size.")

    @staticmethod
    def _is_extension(filename: str, extension: str) -> bool:
        return f".{extension}" == os.path.splitext(filename)[1].lower()

    @staticmethod
    def _extension_for(pil_fmt: str) -> str:
        return {
            "JPEG": ".jpg",
            "PNG": ".png",
            "WEBP": ".webp",
            "AVIF": ".avif",
            "ICO": ".ico",
            "TIFF": ".tiff",
            "BMP": ".bmp",
        }[pil_fmt]

    def _safe_stem(self, filename: str) -> str:
        stem = os.path.splitext(filename or "")[0]
        cleaned = _SAFE_NAME.sub("-", stem).strip("-.")
        return (cleaned or "image")[:64]

    def _output_filename(
        self, source_filename: str, extension: str, page: int | None
    ) -> str:
        stem = self._safe_stem(source_filename)
        suffix = f"_page-{page}" if page is not None else ""
        return f"{stem}{suffix}{extension}"

    @staticmethod
    def _register_heif() -> None:
        if importlib.util.find_spec("pillow_heif") is not None:
            try:
                import pillow_heif

                pillow_heif.register_heif_opener()  # type: ignore[attr-defined]
            except Exception:
                logger.warning("pillow_heif registration failed; HEIC inputs will be rejected")

    def _load_source(self, filename: str, data: bytes) -> Image.Image:
        """Load image bytes honouring PSD flattening and decoding budgets."""
        if self._is_extension(filename, "psd"):
            return self._flatten_psd(data)
        return self._load_image(data)

    def _flatten_psd(self, data: bytes) -> Image.Image:
        try:
            from psd_tools import PSDImage
        except ImportError as exc:
            raise ImageFeatureDisabledError(
                "PSD support is not available (psd-tools is not installed)."
            ) from exc
        try:
            psd = PSDImage.open(io.BytesIO(data))
            flattened = psd.composite()
        except Exception as exc:
            logger.warning("psd_parse_failed error=%s", exc)
            raise ImageFormatUnsupportedError(
                "The supplied PSD file could not be rendered."
            ) from exc
        if flattened is None:
            raise ImageFormatUnsupportedError("The supplied PSD contains no composite data.")
        if flattened.mode not in ("RGB", "RGBA"):
            flattened = flattened.convert("RGBA" if "A" in flattened.getbands() else "RGB")
        if flattened.width * flattened.height > self._settings.max_image_pixels:
            raise ResourceLimitError("PSD dimensions exceed the allowed pixel budget.")
        return flattened

    def _load_image(self, data: bytes) -> Image.Image:
        if len(data) > self._settings.max_image_bytes:
            raise ResourceLimitError("Image exceeds the allowed upload size.")
        try:
            img = Image.open(io.BytesIO(data))
        except Exception as exc:
            raise ImageFormatUnsupportedError(
                "The supplied file is not a supported image."
            ) from exc
        width, height = img.size
        if width <= 0 or height <= 0 or width * height > self._settings.max_image_pixels:
            img.close()
            raise ResourceLimitError("Image dimensions exceed the allowed pixel budget.")
        try:
            img.load()
        except Exception as exc:
            img.close()
            raise ImageFormatUnsupportedError("The supplied image could not be decoded.") from exc
        return img

    def _resize_width(self, img: Image.Image, target_width: int) -> Image.Image:
        if target_width > self._settings.image_width_max:
            raise ResourceLimitError("Requested width exceeds the allowed maximum.")
        if img.width <= 0:
            raise ImageProcessingError("Original image has no width.")
        ratio = target_width / float(img.width)
        new_size = (target_width, max(1, int(img.height * ratio)))
        return img.resize(new_size, Image.Resampling.LANCZOS)

    def _resize_to_canvas(
        self,
        img: Image.Image,
        target_width: int,
        target_height: int,
        mode: str,
        margin_mm: float,
        auto_rotate: bool,
    ) -> Image.Image:
        if target_width <= 0 or target_height <= 0:
            raise ImageProcessingError("Canvas dimensions must be positive.")
        if target_width > self._settings.image_canvas_max_dimension or (
            target_height > self._settings.image_canvas_max_dimension
        ):
            raise ResourceLimitError("Canvas dimensions exceed the allowed maximum.")
        if mode not in _PDF_SCALE_MODES:
            raise ImageFormatUnsupportedError("Canvas mode must be 'fit' or 'fill'.")

        img = self._flatten_for_canvas(img)
        target_width, target_height = self._maybe_rotate_canvas(
            img, target_width, target_height, auto_rotate
        )
        margin_px = round(margin_mm * 72.0 / 25.4)
        max_margin = min((target_width - 1) // 2, (target_height - 1) // 2)
        margin_px = max(0, min(margin_px, max_margin))
        inner_w = target_width - (2 * margin_px)
        inner_h = target_height - (2 * margin_px)
        if inner_w <= 0 or inner_h <= 0:
            raise ImageProcessingError("Margin is too large for the target canvas.")

        ratio = (max if mode == "fill" else min)(inner_w / img.width, inner_h / img.height)
        new_size = (max(1, int(img.width * ratio)), max(1, int(img.height * ratio)))
        resized = img.resize(new_size, Image.Resampling.LANCZOS)

        base = Image.new("RGB", (target_width, target_height), (255, 255, 255))
        if mode == "fill":
            left = max(0, (resized.width - inner_w) // 2)
            top = max(0, (resized.height - inner_h) // 2)
            right = left + inner_w
            bottom = top + inner_h
            cropped = resized.crop((left, top, right, bottom))
            base.paste(cropped.convert("RGB"), (margin_px, margin_px))
        else:
            offset_x = margin_px + (inner_w - resized.width) // 2
            offset_y = margin_px + (inner_h - resized.height) // 2
            if resized.mode in ("RGBA", "LA"):
                base.paste(
                    resized.convert("RGB"),
                    (offset_x, offset_y),
                    mask=resized.getchannel("A"),
                )
            else:
                base.paste(resized.convert("RGB"), (offset_x, offset_y))
        return base

    @staticmethod
    def _flatten_for_canvas(img: Image.Image) -> Image.Image:
        try:
            return ImageOps.exif_transpose(img)
        except Exception:
            return img

    @staticmethod
    def _maybe_rotate_canvas(
        img: Image.Image,
        target_width: int,
        target_height: int,
        auto_rotate: bool,
    ) -> tuple[int, int]:
        if not auto_rotate:
            return target_width, target_height
        if (img.width > img.height) != (target_width > target_height):
            return target_height, target_width
        return target_width, target_height

    def _prepare_for_save(self, img: Image.Image, pil_fmt: str) -> Image.Image:
        if pil_fmt == "JPEG":
            return self._normalize_for_jpeg(img)
        if pil_fmt in {"ICO", "AVIF"}:
            return img.convert("RGBA") if img.mode not in {"RGB", "RGBA"} else img
        if pil_fmt == "BMP" and img.mode not in {"RGB", "RGBA"}:
            return img.convert("RGBA" if "A" in img.getbands() else "RGB")
        return img

    @staticmethod
    def _normalize_for_jpeg(img: Image.Image) -> Image.Image:
        with contextlib.suppress(Exception):
            img = ImageOps.exif_transpose(img)
        if img.mode in ("RGBA", "LA"):
            background = Image.new("RGB", img.size, (255, 255, 255))
            alpha = img.getchannel("A")
            background.paste(img.convert("RGB"), mask=alpha)
            return background
        if img.mode != "RGB":
            return img.convert("RGB")
        return img

    def _encode(self, img: Image.Image, pil_fmt: str, quality: int) -> bytes:
        prepared = self._prepare_for_save(img, pil_fmt)
        buf = io.BytesIO()
        if pil_fmt == "JPEG":
            prepared.save(
                buf,
                format="JPEG",
                quality=quality,
                optimize=True,
                progressive=True,
                subsampling="4:2:0",
            )
        elif pil_fmt == "WEBP":
            prepared.save(buf, format="WEBP", quality=quality, method=6)
        elif pil_fmt == "AVIF":
            prepared.save(buf, format="AVIF", quality=quality)
        elif pil_fmt == "TIFF":
            prepared.save(buf, format="TIFF", compression="tiff_deflate")
        else:
            prepared.save(buf, format=pil_fmt)
        output = buf.getvalue()
        if len(output) > self._settings.image_max_output_bytes:
            raise ResourceLimitError("Converted image exceeds the allowed output size.")
        return output

    def _encode_under_target(
        self, img: Image.Image, pil_fmt: str, target_size_kb: int
    ) -> tuple[int, bytes]:
        if target_size_kb < self._settings.image_target_size_min_kb:
            raise ImageProcessingError(
                f"Target size must be at least {self._settings.image_target_size_min_kb} KB."
            )
        if target_size_kb > self._settings.image_target_size_max_kb:
            raise ImageProcessingError(
                f"Target size cannot exceed {self._settings.image_target_size_max_kb} KB."
            )
        target_bytes = int(target_size_kb * 1024 * 0.98)

        def encoder(quality: int) -> bytes:
            return self._encode(img, pil_fmt, quality)

        low, high = 10, 95
        best: tuple[int, bytes, int] | None = None
        for _ in range(10):
            if low > high:
                break
            quality = (low + high) // 2
            out = encoder(quality)
            size = len(out)
            if size <= target_bytes:
                best = (quality, out, size)
                low = quality + 1
            else:
                high = quality - 1
        if best is None:
            out = encoder(10)
            best = (10, out, len(out))
        return best[0], best[1]

    # ── PDF generation ──────────────────────────────────────────────────────

    def _make_pdf(
        self,
        img: Image.Image,
        *,
        pdf_preset: str | None,
        pdf_scale: str,
        pdf_margin_mm: float | None,
        pdf_paginate: bool,
        pdf_quality: str,
    ) -> bytes:
        from fpdf import FPDF

        preset_key = self._normalize_value(pdf_preset, "original")
        if preset_key not in _PDF_PRESETS:
            raise ImageFormatUnsupportedError(f"Unsupported PDF preset: '{preset_key}'.")
        preset = _PDF_PRESETS[preset_key]

        scale_key = self._normalize_value(pdf_scale, "fit")
        if scale_key not in _PDF_SCALE_MODES:
            raise ImageFormatUnsupportedError(f"Unsupported PDF scale mode: '{scale_key}'.")
        quality_key = self._normalize_value(pdf_quality, "high")
        if quality_key not in _PDF_QUALITY:
            raise ImageFormatUnsupportedError(f"Unsupported PDF quality preset: '{quality_key}'.")
        quality = _PDF_QUALITY[quality_key]
        dpi = int(quality["dpi"] or 220)
        jpeg_quality = int(quality["jpeg_quality"] or 82)
        original_max = quality["original_max_dimension"]

        prepared = self._normalize_for_pdf(img)
        if preset["size"] is None:
            page_w, page_h = prepared.size
            if original_max is not None and max(prepared.size) > original_max:
                prepared = prepared.copy()
                prepared.thumbnail((original_max, original_max), Image.Resampling.LANCZOS)
            return self._render_pdf(
                FPDF(unit="pt", format=(page_w, page_h)),
                prepared,
                x=0,
                y=0,
                w=page_w,
                h=page_h,
                jpeg_quality=jpeg_quality,
            )

        page_w, page_h = preset["size"]
        auto_rotate = bool(preset["auto_rotate"])
        if auto_rotate and (prepared.width > prepared.height) != (page_w > page_h):
            page_w, page_h = page_h, page_w

        margin_mm = pdf_margin_mm if pdf_margin_mm is not None else preset["margin_mm"]
        margin_pt = self._mm_to_pt(margin_mm)
        inner_w = page_w - (2 * margin_pt)
        inner_h = page_h - (2 * margin_pt)
        if inner_w <= 0 or inner_h <= 0:
            raise ImageProcessingError("PDF margin is too large for the page size.")

        pdf = FPDF(unit="pt", format=(page_w, page_h))

        if pdf_paginate:
            return self._render_paginated(
                pdf,
                prepared,
                inner_w,
                inner_h,
                margin_pt,
                dpi=dpi,
                jpeg_quality=jpeg_quality,
            )

        if scale_key == "fill":
            prepared = self._crop_to_aspect(prepared, inner_w / inner_h)
            target_w, target_h = inner_w, inner_h
            offset_x, offset_y = margin_pt, margin_pt
        else:
            scale = min(inner_w / prepared.width, inner_h / prepared.height)
            target_w = prepared.width * scale
            target_h = prepared.height * scale
            offset_x = margin_pt + (inner_w - target_w) / 2
            offset_y = margin_pt + (inner_h - target_h) / 2

        prepared = self._downsample_for_render(prepared, target_w, target_h, dpi)
        return self._render_pdf(
            pdf, prepared, x=offset_x, y=offset_y, w=target_w, h=target_h, jpeg_quality=jpeg_quality
        )

    @staticmethod
    def _normalize_value(value: str | None, default: str) -> str:
        if not value:
            return default
        cleaned = value.strip().lower().replace("_", "-").replace(" ", "-")
        return cleaned or default

    @staticmethod
    def _mm_to_pt(mm: float) -> float:
        return mm * 72.0 / 25.4

    @staticmethod
    def _normalize_for_pdf(img: Image.Image) -> Image.Image:
        with contextlib.suppress(Exception):
            img = ImageOps.exif_transpose(img)
        if img.mode in ("RGBA", "LA"):
            background = Image.new("RGB", img.size, (255, 255, 255))
            alpha = img.getchannel("A")
            background.paste(img.convert("RGB"), mask=alpha)
            return background
        if img.mode != "RGB":
            return img.convert("RGB")
        return img

    @staticmethod
    def _crop_to_aspect(img: Image.Image, target_ratio: float) -> Image.Image:
        img_ratio = img.width / img.height
        if img_ratio > target_ratio:
            new_width = round(img.height * target_ratio)
            left = max(0, (img.width - new_width) // 2)
            return img.crop((left, 0, left + new_width, img.height))
        new_height = round(img.width / target_ratio)
        top = max(0, (img.height - new_height) // 2)
        return img.crop((0, top, img.width, top + new_height))

    @staticmethod
    def _downsample_for_render(
        img: Image.Image, width_pt: float, height_pt: float, dpi: int
    ) -> Image.Image:
        max_w = max(1, round(width_pt * dpi / 72.0))
        max_h = max(1, round(height_pt * dpi / 72.0))
        if img.width <= max_w and img.height <= max_h:
            return img
        resized = img.copy()
        resized.thumbnail((max_w, max_h), Image.Resampling.LANCZOS)
        return resized

    def _render_paginated(
        self,
        pdf: Any,
        img: Image.Image,
        inner_w: float,
        inner_h: float,
        margin_pt: float,
        *,
        dpi: int,
        jpeg_quality: int,
    ) -> bytes:
        scale = inner_w / img.width
        if scale <= 0:
            raise ImageProcessingError("Invalid scale for PDF pagination.")
        slice_height_px = inner_h / scale
        if slice_height_px <= 0:
            raise ImageProcessingError("Invalid slice height for PDF pagination.")
        page_count = max(1, math.ceil(img.height / slice_height_px))
        if page_count > self._settings.image_max_pdf_pages:
            raise ResourceLimitError("Paged PDF exceeds the allowed page limit.")

        for page_index in range(page_count):
            top_px = page_index * slice_height_px
            bottom_px = min((page_index + 1) * slice_height_px, img.height)
            top_i = round(top_px)
            bottom_i = round(bottom_px)
            if bottom_i <= top_i:
                continue
            slice_img = img.crop((0, top_i, img.width, bottom_i))
            target_h = (bottom_px - top_px) * scale
            slice_img = self._downsample_for_render(slice_img, inner_w, target_h, dpi)
            pdf.add_page()
            self._render_pdf(
                pdf,
                slice_img,
                x=margin_pt,
                y=margin_pt,
                w=inner_w,
                h=target_h,
                jpeg_quality=jpeg_quality,
                close_pdf=False,
            )
        output: bytes = pdf.output()
        if isinstance(output, bytearray):
            output = bytes(output)
        if isinstance(output, str):
            output = output.encode("latin-1")
        if len(output) > self._settings.image_max_output_bytes:
            raise ResourceLimitError("PDF exceeds the allowed output size.")
        return output

    def _render_pdf(
        self,
        pdf: Any,
        img: Image.Image,
        *,
        x: float,
        y: float,
        w: float,
        h: float,
        jpeg_quality: int,
        close_pdf: bool = True,
    ) -> bytes:
        tmp_path: str | None = None
        try:
            if close_pdf:
                pdf.add_page()
            with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as tmp:
                tmp_path = tmp.name
                img.save(
                    tmp,
                    format="JPEG",
                    quality=jpeg_quality,
                    optimize=True,
                    progressive=True,
                )
            pdf.image(tmp_path, x=x, y=y, w=w, h=h)
            if not close_pdf:
                return b""
            output: bytes = pdf.output()
            if isinstance(output, bytearray):
                output = bytes(output)
            if isinstance(output, str):
                output = output.encode("latin-1")
            if len(output) > self._settings.image_max_output_bytes:
                raise ResourceLimitError("PDF exceeds the allowed output size.")
            return output
        finally:
            if tmp_path:
                with contextlib.suppress(OSError):
                    os.unlink(tmp_path)
