"""Image processing endpoints.

Local, in-memory conversion and resizing of user-supplied images: raster format
conversion (JPEG/PNG/WEBP/AVIF/ICO/TIFF/BMP), image->PDF with page presets,
PDF->per-page rasterization (ZIP), PSD flattening, HEIF/HEIC decoding, target
size optimisation and optional AI background removal. All outputs are re-encoded
in memory and never persist files server-side.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, File, Form, UploadFile
from fastapi.responses import Response

from app.core.dependencies import get_image_service
from app.core.exceptions import ImageProcessingError
from app.schemas.image_tools import ImageFormatsResponse
from app.services.image_service import ImageService

router = APIRouter(prefix="/image", tags=["Image Processing"])

_BINARY_200 = {
    "description": "Processed file bytes (binary).",
    "content": {
        "application/octet-stream": {"schema": {"type": "string", "format": "binary"}}
    },
}


@router.get(
    "/formats",
    response_model=ImageFormatsResponse,
    summary="List supported image formats and capabilities",
    description=(
        "Reports the raster formats this deployment can read and write, the "
        "available PDF presets/quality settings, whether AI background removal "
        "is enabled and the enforced processing limits."
    ),
)
async def image_formats(
    service: ImageService = Depends(get_image_service),
) -> dict[str, Any]:
    return service.capabilities()


@router.post(
    "/convert",
    response_class=Response,
    responses={200: _BINARY_200},
    summary="Convert an image to another format or to PDF",
    description=(
        "Accepts a single raster image (JPEG, PNG, WEBP, AVIF, TIFF, BMP, GIF, "
        "ICO, HEIC/HEIF or a flattened PSD) and re-encodes it as JPEG, PNG, "
        "WEBP, AVIF, ICO, TIFF, BMP or PDF. Outputs are re-encoded and never "
        "carry EXIF/location metadata. Use `width` to downscale, `target_size_kb` "
        "to binary-search the best quality under a byte budget (JPEG/WebP/AVIF), "
        "or the `pdf_*` fields when targeting PDF. PDF inputs are handled by "
        "`/image/rasterize` instead."
    ),
)
async def image_convert(
    file: UploadFile = File(...),
    format: str = Form(
        ..., description="Output format: jpeg, png, webp, avif, ico, tiff, bmp or pdf."
    ),
    quality: int = Form(85, ge=1, le=100, description="Encoding quality (raster outputs)."),
    width: int | None = Form(None, gt=0, description="Optional output width in pixels."),
    target_size_kb: int | None = Form(
        None, gt=0, description="Target output size in KB (JPEG/WebP/AVIF only)."
    ),
    pdf_preset: str | None = Form(
        None, description="PDF page preset (e.g. a4-auto, letter-portrait, mobile-portrait)."
    ),
    pdf_scale: str = Form("fit", description="PDF fit/fill placement mode."),
    pdf_margin_mm: float | None = Form(None, ge=0, description="PDF margin in millimetres."),
    pdf_paginate: bool = Form(False, description="Split a tall image across PDF pages."),
    pdf_quality: str = Form("high", description="PDF render quality: small, medium, high, ultra."),
    service: ImageService = Depends(get_image_service),
) -> Response:
    data = await file.read()
    result = await service.convert(
        filename=file.filename or "image",
        data=data,
        output_format=format,
        quality=quality,
        width=width,
        target_size_kb=target_size_kb,
        pdf_preset=pdf_preset,
        pdf_scale=pdf_scale,
        pdf_margin_mm=pdf_margin_mm,
        pdf_paginate=pdf_paginate,
        pdf_quality=pdf_quality,
    )
    return _file_response(result)


@router.post(
    "/resize",
    response_class=Response,
    responses={200: _BINARY_200},
    summary="Resize an image by width and/or fit it onto a canvas",
    description=(
        "Shrinks an image to a target `width` (LANCZOS, preserving aspect) and/or "
        "places it on a white canvas (`canvas_width`/`canvas_height` must be "
        "provided together) using fit or fill placement with an optional margin. "
        "Output format defaults to PNG."
    ),
)
async def image_resize(
    file: UploadFile = File(...),
    width: int | None = Form(None, gt=0, description="Target width in pixels (aspect preserved)."),
    canvas_width: int | None = Form(None, gt=0, description="Canvas width in pixels."),
    canvas_height: int | None = Form(None, gt=0, description="Canvas height in pixels."),
    mode: str = Form("fit", description="Canvas placement: fit or fill."),
    margin_mm: float = Form(0.0, ge=0, description="Canvas margin in millimetres."),
    auto_rotate: bool = Form(False, description="Rotate the canvas to match image orientation."),
    output_format: str = Form("png", description="Output format: png, jpeg, webp, avif, bmp."),
    service: ImageService = Depends(get_image_service),
) -> Response:
    if (canvas_width is None) != (canvas_height is None):
        raise ImageProcessingError("canvas_width and canvas_height must be provided together.")
    data = await file.read()
    result = await service.resize(
        filename=file.filename or "image",
        data=data,
        width=width,
        canvas_width=canvas_width,
        canvas_height=canvas_height,
        mode=mode,
        margin_mm=margin_mm,
        auto_rotate=auto_rotate,
        output_format=output_format,
    )
    return _file_response(result)


@router.post(
    "/rasterize",
    response_class=Response,
    responses={200: _BINARY_200},
    summary="Rasterize a PDF into per-page images (ZIP)",
    description=(
        "Renders each page of an uploaded PDF into a JPEG or PNG image and "
        "returns the pages as a ZIP archive. Page count and DPI are capped by "
        "deployment limits."
    ),
)
async def image_rasterize(
    file: UploadFile = File(...),
    page_format: str = Form("jpeg", description="Page image format: jpeg or png."),
    dpi: int = Form(150, ge=36, description="Rendering DPI (capped server-side)."),
    service: ImageService = Depends(get_image_service),
) -> Response:
    data = await file.read()
    result = await service.rasterize_pdf(
        filename=file.filename or "document",
        data=data,
        page_format=page_format,
        dpi=dpi,
    )
    return _file_response(result, extra={"X-Image-Pages": str(result.item_count)})


@router.post(
    "/background",
    response_class=Response,
    responses={200: _BINARY_200},
    summary="Remove an image background using AI",
    description=(
        "Runs rembg (u2net) over a single image and returns a transparent PNG "
        "(or AVIF). Disabled unless IMAGE_BACKGROUND_REMOVAL_ENABLED=true and "
        "the optional [image-ai] extra is installed."
    ),
)
async def image_remove_background(
    file: UploadFile = File(...),
    output_format: str = Form("png", description="Output format: png or avif."),
    service: ImageService = Depends(get_image_service),
) -> Response:
    data = await file.read()
    result = await service.remove_background(
        filename=file.filename or "image",
        data=data,
        output_format=output_format,
    )
    return _file_response(result)


def _file_response(
    result: Any, extra: dict[str, str] | None = None
) -> Response:
    headers = {
        "Content-Disposition": f'attachment; filename="{result.filename}"',
        "X-Image-Format": result.format,
        "X-Image-Bytes": str(len(result.content)),
    }
    if getattr(result, "width", None) is not None:
        headers["X-Image-Width"] = str(result.width)
        headers["X-Image-Height"] = str(result.height)
    if extra:
        headers.update(extra)
    return Response(content=result.content, media_type=result.media_type, headers=headers)
