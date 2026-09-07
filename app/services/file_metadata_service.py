"""File and image metadata extraction using magic bytes and Pillow."""
from __future__ import annotations

import base64
import io
from typing import Any, cast

from app.core.config import Settings
from app.core.exceptions import ResourceLimitError

# ── Magic-byte table ──────────────────────────────────────────────────────────
# Each entry: (offset, magic_bytes, mime_type, extension, description)
_MAGIC: list[tuple[int, bytes, str, str, str]] = [
    (0, b"\x89PNG\r\n\x1a\n", "image/png", ".png", "PNG image"),
    (0, b"\xff\xd8\xff", "image/jpeg", ".jpg", "JPEG image"),
    (0, b"GIF87a", "image/gif", ".gif", "GIF image (87a)"),
    (0, b"GIF89a", "image/gif", ".gif", "GIF image (89a)"),
    (0, b"RIFF", "image/webp", ".webp", "WebP image"),
    (0, b"\x42\x4d", "image/bmp", ".bmp", "BMP image"),
    (0, b"\x49\x49\x2a\x00", "image/tiff", ".tiff", "TIFF image (little-endian)"),
    (0, b"\x4d\x4d\x00\x2a", "image/tiff", ".tiff", "TIFF image (big-endian)"),
    (0, b"\x00\x00\x01\x00", "image/x-icon", ".ico", "ICO icon"),
    (0, b"\x00\x00\x02\x00", "image/x-icon", ".ico", "CUR cursor"),
    (0, b"%PDF", "application/pdf", ".pdf", "PDF document"),
    (0, b"\x1f\x8b", "application/gzip", ".gz", "Gzip compressed data"),
    (0, b"PK\x03\x04", "application/zip", ".zip", "ZIP archive"),
    (0, b"PK\x05\x06", "application/zip", ".zip", "ZIP archive (empty)"),
    (0, b"BZ", "application/x-bzip2", ".bz2", "Bzip2 compressed data"),
    (0, b"\xfd7zXZ", "application/x-xz", ".xz", "XZ compressed data"),
    (0, b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed", ".7z", "7-Zip archive"),
    (0, b"\x04\x22\x4d\x18", "application/x-lz4", ".lz4", "LZ4 compressed data"),
    (0, b"Rar!\x1a\x07", "application/x-rar-compressed", ".rar", "RAR archive"),
    (0, b"<!DOCTYPE", "text/html", ".html", "HTML document"),
    (0, b"<html", "text/html", ".html", "HTML document"),
    (0, b"<?xml", "text/xml", ".xml", "XML document"),
    (0, b"{", "application/json", ".json", "JSON (possible)"),
    (0, b"[", "application/json", ".json", "JSON array (possible)"),
    (0, b"\x89PNG", "image/png", ".png", "PNG image"),
    (0, b"\x00\x00\x00\x1c\x66\x74\x79\x70", "video/mp4", ".mp4", "MP4 video"),
    (0, b"\x00\x00\x00\x20\x66\x74\x79\x70", "video/mp4", ".mp4", "MP4 video"),
    (0, b"\x1a\x45\xdf\xa3", "video/webm", ".webm", "WebM video"),
    (0, b"\x4f\x67\x67\x53", "audio/ogg", ".ogg", "OGG audio"),
    (0, b"ID3", "audio/mpeg", ".mp3", "MP3 audio (ID3 tag)"),
    (0, b"\xff\xfb", "audio/mpeg", ".mp3", "MP3 audio"),
    (0, b"\xff\xf3", "audio/mpeg", ".mp3", "MP3 audio"),
    (0, b"fLaC", "audio/flac", ".flac", "FLAC audio"),
    (0, b"\x00\x00\x00\x01\x67", "video/h264", ".h264", "H.264 video"),
    (0, b"\x00\x00\x00\x01\x68", "video/h264", ".h264", "H.264 video (SPS)"),
    (0, b"\x00\x00\x00\x01\x65", "video/h264", ".h264", "H.264 video (IDR)"),
    (4, b"ftypavif", "image/avif", ".avif", "AVIF image"),
    (4, b"ftypheic", "image/heic", ".heic", "HEIC image"),
    (4, b"ftypmif1", "image/heif", ".heif", "HEIF image"),
]

# WebP RIFF container → check for VP8/VP8L/VP8X after "WEBP" at offset 8
_WEBP_TYPES = {
    b"VP8 ": "image/webp",
    b"VP8L": "image/webp",
    b"VP8X": "image/webp",
}


def _sniff_magic(data: bytes) -> tuple[str, str | None, str]:
    """Return (mime_type, extension, description) from magic bytes."""
    for offset, magic, mime, ext, desc in _MAGIC:
        if data[offset:offset + len(magic)] == magic:
            # WebP special case: verify RIFF container sub-type.
            if mime == "image/webp" and len(data) >= 16:
                sub = data[12:16]
                if sub in _WEBP_TYPES:
                    return mime, ext, desc
                # False positive on generic RIFF; keep mime but note.
            return mime, ext, desc
    return "application/octet-stream", None, "Unknown binary data"


class FileMetadataService:
    """Extract metadata from files without uploading."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._max_image_bytes = settings.max_image_bytes if settings else 7_500_000
        self._max_image_pixels = settings.max_image_pixels if settings else 40_000_000

    @staticmethod
    def extract_file_metadata(data_b64: str, filename: str | None = None) -> dict[str, Any]:
        try:
            raw = base64.b64decode(data_b64, validate=True)
        except Exception as exc:
            raise ValueError("Invalid Base64 data.") from exc

        mime, ext, desc = _sniff_magic(raw)

        # Extension override from filename.
        if filename and "." in filename:
            file_ext = "." + filename.rsplit(".", 1)[-1].lower()
            ext = file_ext

        return {
            "mime_type": mime,
            "extension": ext,
            "size_bytes": len(raw),
            "magic_match": True,
            "description": desc,
        }

    def extract_image_metadata(self, data_b64: str, filename: str | None = None) -> dict[str, Any]:
        try:
            raw = base64.b64decode(data_b64, validate=True)
        except Exception:
            return {
                "format": None, "width": None, "height": None, "mode": None,
                "has_exif": False, "exif": {}, "icc_profile": None,
                "is_animated": False, "frame_count": 1,
                "error": "Invalid Base64 data.",
            }

        if len(raw) > self._max_image_bytes:
            raise ResourceLimitError("Image exceeds the allowed decoded size.")

        try:
            from PIL import Image
            from PIL.ExifTags import GPSTAGS, TAGS

            Image.MAX_IMAGE_PIXELS = self._max_image_pixels
            img = Image.open(io.BytesIO(raw))
            width, height = img.size
            if width <= 0 or height <= 0 or width * height > self._max_image_pixels:
                raise ResourceLimitError("Image dimensions exceed the allowed pixel budget.")
            img.load()

            fmt = img.format
            mode = img.mode
            is_animated = getattr(img, "is_animated", False)
            frame_count = getattr(img, "n_frames", 1)

            has_exif = False
            exif_data: dict[str, str] = {}
            icc_profile = None

            if hasattr(img, "_getexif") and img._getexif():
                has_exif = True
                raw_exif = img._getexif()
                for tag_id, value in raw_exif.items():
                    tag_name = TAGS.get(tag_id, str(tag_id))
                    # Skip binary/complex values.
                    if isinstance(value, (str, int, float)):
                        exif_data[tag_name] = str(value)
                    elif isinstance(value, bytes):
                        exif_data[tag_name] = f"<{len(value)} bytes>"
                    elif isinstance(value, tuple) and tag_name == "GPSInfo":
                        gps_map: dict[int, Any] = cast("dict[int, Any]", value)
                        for gps_id, gps_val in gps_map.items():
                            gps_tag = GPSTAGS.get(gps_id, str(gps_id))
                            if isinstance(gps_val, (str, int, float)):
                                exif_data[f"GPS:{gps_tag}"] = str(gps_val)

            if img.info.get("icc_profile"):
                try:
                    import PIL.IcmImagePlugin  # noqa: F401 - registers ICC profile reader
                    icc = img.info["icc_profile"]
                    if hasattr(icc, "profile"):
                        icc_profile = getattr(icc.profile, "profile_description", "Unknown")
                    else:
                        icc_profile = "ICC profile present"
                except Exception:
                    icc_profile = "ICC profile present"

            return {
                "format": fmt,
                "width": width,
                "height": height,
                "mode": mode,
                "has_exif": has_exif,
                "exif": exif_data,
                "icc_profile": icc_profile,
                "is_animated": is_animated,
                "frame_count": frame_count,
                "error": None,
            }

        except ResourceLimitError:
            raise
        except ImportError:
            return {
                "format": None, "width": None, "height": None, "mode": None,
                "has_exif": False, "exif": {}, "icc_profile": None,
                "is_animated": False, "frame_count": 1,
                "error": "Pillow is not installed.",
            }
        except Exception as exc:
            return {
                "format": None, "width": None, "height": None, "mode": None,
                "has_exif": False, "exif": {}, "icc_profile": None,
                "is_animated": False, "frame_count": 1,
                "error": f"Failed to parse image: {exc}",
            }
