"""Image preprocessing — normalize orientation before pipeline processing."""

from __future__ import annotations

import logging
import re
from io import BytesIO

import pytesseract
from PIL import Image, ImageOps, UnidentifiedImageError

logger = logging.getLogger(__name__)


def normalize_image(file_content: bytes, filename: str) -> bytes:
    """Apply EXIF auto-rotation and OSD fallback to normalize image orientation.

    1. EXIF transpose — corrects phone-camera orientation metadata.
    2. Tesseract OSD fallback — detects rotation when no EXIF data exists.
    3. Re-encode in the original format (JPEG or PNG).

    Returns the original bytes unchanged if the content is not a valid image.
    """
    try:
        img = Image.open(BytesIO(file_content))
    except (UnidentifiedImageError, Exception):
        logger.debug("Cannot open '%s' as image, skipping preprocessing", filename)
        return file_content
    original_size = img.size

    # Step 1: EXIF auto-rotation
    img = ImageOps.exif_transpose(img)
    exif_rotated = img.size != original_size

    if exif_rotated:
        logger.info("EXIF orientation applied for '%s'", filename)

    # Step 2: Tesseract OSD fallback (only if EXIF didn't rotate)
    if not exif_rotated:
        try:
            osd = pytesseract.image_to_osd(img)
            match = re.search(r"Rotate:\s*(\d+)", osd)
            if match:
                angle = int(match.group(1))
                if angle != 0:
                    img = img.rotate(angle, expand=True)
                    logger.info("OSD rotation applied: %d degrees for '%s'", angle, filename)
        except Exception:
            logger.debug("OSD detection failed for '%s', using image as-is", filename)

    # Step 3: Re-encode in original format
    fmt = _resolve_format(filename)
    buf = BytesIO()
    save_kwargs: dict[str, object] = {}
    if fmt == "JPEG":
        save_kwargs["quality"] = 95
        if img.mode == "RGBA":
            img = img.convert("RGB")
    img.save(buf, format=fmt, **save_kwargs)
    return buf.getvalue()


def _resolve_format(filename: str) -> str:
    """Map filename extension to PIL format string."""
    if filename.lower().endswith(".png"):
        return "PNG"
    return "JPEG"
