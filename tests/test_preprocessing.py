"""Unit tests for the image preprocessing module.

Covers EXIF auto-rotation, Tesseract OSD fallback, graceful failure,
format preservation (JPEG / PNG), and document region extraction.
"""

from __future__ import annotations

from io import BytesIO
from unittest.mock import patch

import cv2
import numpy as np
import pytest
from PIL import Image

from app.pipeline.preprocessing import extract_document_region, normalize_image


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_image(
    width: int = 100,
    height: int = 200,
    fmt: str = "JPEG",
    exif_orientation: int | None = None,
) -> bytes:
    """Create a simple image and return its bytes.

    If *exif_orientation* is given, embed a minimal EXIF block with the
    specified Orientation tag.
    """
    img = Image.new("RGB", (width, height), color=(128, 200, 50))
    buf = BytesIO()

    if exif_orientation is not None and fmt == "JPEG":
        import piexif

        exif_dict: dict = {"0th": {piexif.ImageIFD.Orientation: exif_orientation}}
        exif_bytes = piexif.dump(exif_dict)
        img.save(buf, format=fmt, exif=exif_bytes, quality=95)
    else:
        save_kwargs: dict = {"quality": 95} if fmt == "JPEG" else {}
        img.save(buf, format=fmt, **save_kwargs)

    return buf.getvalue()


def _image_from_bytes(data: bytes) -> Image.Image:
    """Open an image from raw bytes."""
    return Image.open(BytesIO(data))


# ---------------------------------------------------------------------------
# EXIF rotation tests
# ---------------------------------------------------------------------------


class TestExifRotation:
    """SPEC-IMG-01: EXIF auto-rotation."""

    def test_exif_orientation_applied(self) -> None:
        """Orientation tag 6 (90 CW) should transpose a 100x200 image to 200x100."""
        raw = _make_image(width=100, height=200, fmt="JPEG", exif_orientation=6)
        result = normalize_image(raw, "photo.jpg")
        out = _image_from_bytes(result)
        assert out.size == (200, 100)

    def test_no_exif_returns_same_dimensions(self) -> None:
        """Image without EXIF data keeps original dimensions (OSD mocked to 0)."""
        raw = _make_image(width=100, height=200, fmt="JPEG")
        with patch("app.pipeline.preprocessing.pytesseract") as mock_tess:
            mock_tess.image_to_osd.return_value = "Rotate: 0\nOrientation in degrees: 0"
            result = normalize_image(raw, "photo.jpg")
        out = _image_from_bytes(result)
        assert out.size == (100, 200)


# ---------------------------------------------------------------------------
# OSD fallback tests
# ---------------------------------------------------------------------------


class TestOsdFallback:
    """SPEC-IMG-02: Tesseract OSD fallback."""

    def test_osd_rotation_applied(self) -> None:
        """When OSD reports Rotate: 90, the image should be rotated."""
        raw = _make_image(width=100, height=200, fmt="JPEG")
        with patch("app.pipeline.preprocessing.pytesseract") as mock_tess:
            mock_tess.image_to_osd.return_value = (
                "Page number: 0\n"
                "Orientation in degrees: 90\n"
                "Rotate: 90\n"
                "Orientation confidence: 1.0\n"
                "Script: Latin\n"
                "Script confidence: 1.0"
            )
            result = normalize_image(raw, "photo.jpg")
        out = _image_from_bytes(result)
        # 100x200 rotated 90 degrees → 200x100
        assert out.size == (200, 100)

    def test_osd_failure_returns_original(self) -> None:
        """If OSD raises an exception, image is returned unchanged."""
        raw = _make_image(width=100, height=200, fmt="JPEG")
        with patch("app.pipeline.preprocessing.pytesseract") as mock_tess:
            mock_tess.image_to_osd.side_effect = RuntimeError("no osd")
            result = normalize_image(raw, "photo.jpg")
        out = _image_from_bytes(result)
        assert out.size == (100, 200)

    def test_exif_present_skips_osd(self) -> None:
        """When EXIF rotation is applied, OSD should NOT be called."""
        raw = _make_image(width=100, height=200, fmt="JPEG", exif_orientation=6)
        with patch("app.pipeline.preprocessing.pytesseract") as mock_tess:
            normalize_image(raw, "photo.jpg")
            mock_tess.image_to_osd.assert_not_called()


# ---------------------------------------------------------------------------
# Format preservation tests
# ---------------------------------------------------------------------------


class TestFormatPreservation:
    """SPEC-IMG-03: Format preservation."""

    def test_jpeg_format_preserved(self) -> None:
        """JPEG input should produce JPEG output."""
        raw = _make_image(fmt="JPEG")
        with patch("app.pipeline.preprocessing.pytesseract") as mock_tess:
            mock_tess.image_to_osd.return_value = "Rotate: 0"
            result = normalize_image(raw, "scan.jpg")
        out = _image_from_bytes(result)
        assert out.format == "JPEG"

    def test_png_format_preserved(self) -> None:
        """PNG input should produce PNG output."""
        raw = _make_image(fmt="PNG")
        with patch("app.pipeline.preprocessing.pytesseract") as mock_tess:
            mock_tess.image_to_osd.return_value = "Rotate: 0"
            result = normalize_image(raw, "scan.png")
        out = _image_from_bytes(result)
        assert out.format == "PNG"

    def test_rgba_jpeg_converts_to_rgb(self) -> None:
        """RGBA image saved as JPEG should be converted to RGB (no alpha)."""
        img = Image.new("RGBA", (100, 100), color=(128, 200, 50, 255))
        buf = BytesIO()
        img.save(buf, format="PNG")
        raw = buf.getvalue()

        with patch("app.pipeline.preprocessing.pytesseract") as mock_tess:
            mock_tess.image_to_osd.return_value = "Rotate: 0"
            # .jpg extension → JPEG output
            result = normalize_image(raw, "photo.jpg")
        out = _image_from_bytes(result)
        assert out.mode == "RGB"
        assert out.format == "JPEG"


# ---------------------------------------------------------------------------
# Document region extraction helpers
# ---------------------------------------------------------------------------


def _make_document_image(
    bg_width: int = 1200,
    bg_height: int = 900,
    rect_width: int = 800,
    rect_height: int = 500,
    bg_color: int = 40,
    rect_color: int = 240,
) -> bytes:
    """Create a synthetic image: white rectangle on dark background.

    Returns JPEG-encoded bytes.
    """
    img = np.full((bg_height, bg_width, 3), bg_color, dtype=np.uint8)

    x_offset = (bg_width - rect_width) // 2
    y_offset = (bg_height - rect_height) // 2
    img[y_offset : y_offset + rect_height, x_offset : x_offset + rect_width] = rect_color

    _, encoded = cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, 95])
    return encoded.tobytes()


# ---------------------------------------------------------------------------
# Document region extraction tests
# ---------------------------------------------------------------------------


class TestDocumentRegionExtraction:
    """SPEC-DOC-01 to SPEC-DOC-04: Document region extraction."""

    def test_document_detected(self) -> None:
        """White rectangle on dark background should be extracted."""
        raw = _make_document_image(
            bg_width=1200, bg_height=900, rect_width=800, rect_height=500,
        )
        result = extract_document_region(raw, "photo.jpg")
        # Result should be different from input (extraction happened)
        assert result != raw
        # Decode result and check dimensions are close to rectangle size
        buf = np.frombuffer(result, np.uint8)
        img = cv2.imdecode(buf, cv2.IMREAD_COLOR)
        assert img is not None
        h, w = img.shape[:2]
        # Extracted region should be approximately the rectangle dimensions
        assert abs(w - 800) < 20
        assert abs(h - 500) < 20

    def test_small_contour_rejected(self) -> None:
        """Rectangle below min area threshold should be rejected (fallback)."""
        # Small 100x60 rectangle on 1200x900 → ~0.56% area, well below 10%
        raw = _make_document_image(
            bg_width=1200, bg_height=900, rect_width=100, rect_height=60,
        )
        result = extract_document_region(raw, "photo.jpg")
        assert result == raw

    def test_no_rectangle_fallback(self) -> None:
        """Gradient image with no clear rectangle should fallback."""
        # Create a smooth gradient — no sharp edges for Canny to detect
        gradient = np.tile(
            np.linspace(0, 255, 1200, dtype=np.uint8), (900, 1),
        )
        img = cv2.merge([gradient, gradient, gradient])
        _, encoded = cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, 95])
        raw = encoded.tobytes()
        result = extract_document_region(raw, "photo.jpg")
        assert result == raw

    def test_invalid_bytes_fallback(self) -> None:
        """Random invalid bytes should fallback gracefully."""
        raw = b"this is not an image at all"
        result = extract_document_region(raw, "photo.jpg")
        assert result == raw
