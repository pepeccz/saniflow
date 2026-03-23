"""Image preprocessing — normalize orientation before pipeline processing."""

from __future__ import annotations

import logging
import re
from io import BytesIO

import cv2
import numpy as np
import pytesseract
from PIL import Image, ImageOps, UnidentifiedImageError

from app.config import settings

logger = logging.getLogger(__name__)


def _order_points(pts: np.ndarray) -> np.ndarray:
    """Order 4 points as: top-left, top-right, bottom-right, bottom-left."""
    rect = np.zeros((4, 2), dtype=np.float32)
    s = pts.sum(axis=1)
    rect[0] = pts[np.argmin(s)]  # top-left: smallest x+y
    rect[2] = pts[np.argmax(s)]  # bottom-right: largest x+y
    d = np.diff(pts, axis=1)
    rect[1] = pts[np.argmin(d)]  # top-right: smallest x-y
    rect[3] = pts[np.argmax(d)]  # bottom-left: largest x-y
    return rect


def extract_document_region(file_content: bytes, filename: str) -> bytes:
    """Extract document region from a photo using contour detection.

    Uses Canny edge detection + contour approximation to find the largest
    quadrilateral in the image, then applies perspective transform to
    produce a flat, cropped document image.

    Returns original bytes unchanged if no qualifying contour is found.
    """
    try:
        buf = np.frombuffer(file_content, np.uint8)
        img = cv2.imdecode(buf, cv2.IMREAD_COLOR)
        if img is None:
            return file_content

        h, w = img.shape[:2]
        img_area = h * w
        min_area = img_area * settings.DOCUMENT_MIN_AREA_RATIO
        max_area = img_area * 0.95

        # Edge detection
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        blurred = cv2.GaussianBlur(gray, (5, 5), 0)
        edges = cv2.Canny(blurred, 50, 150)
        kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (3, 3))
        edges = cv2.dilate(edges, kernel, iterations=2)

        # Find contours
        contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

        # Find largest quadrilateral
        best_contour = None
        best_area = 0
        for contour in contours:
            area = cv2.contourArea(contour)
            if area < min_area or area > max_area:
                continue
            peri = cv2.arcLength(contour, True)
            approx = cv2.approxPolyDP(contour, 0.02 * peri, True)
            if len(approx) == 4 and area > best_area:
                best_contour = approx
                best_area = area

        if best_contour is None:
            logger.debug("No document contour found in '%s', using original", filename)
            return file_content

        # Perspective transform
        pts = _order_points(best_contour.reshape(4, 2))
        width = int(max(np.linalg.norm(pts[0] - pts[1]), np.linalg.norm(pts[2] - pts[3])))
        height = int(max(np.linalg.norm(pts[0] - pts[3]), np.linalg.norm(pts[1] - pts[2])))

        if width < 100 or height < 100:
            return file_content

        dst = np.array(
            [[0, 0], [width - 1, 0], [width - 1, height - 1], [0, height - 1]],
            dtype=np.float32,
        )
        M = cv2.getPerspectiveTransform(pts.astype(np.float32), dst)
        warped = cv2.warpPerspective(img, M, (width, height))

        # Re-encode
        ext = ".png" if filename.lower().endswith(".png") else ".jpg"
        params = [cv2.IMWRITE_JPEG_QUALITY, 95] if ext == ".jpg" else []
        _, encoded = cv2.imencode(ext, warped, params)
        logger.info(
            "Document region extracted from '%s' (%dx%d -> %dx%d)",
            filename, w, h, width, height,
        )
        return encoded.tobytes()
    except Exception:
        logger.debug("Document region extraction failed, using original")
        return file_content


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
