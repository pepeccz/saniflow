"""Image sanitizer using OpenCV / Pillow.

Blacks out detected PII regions by drawing filled rectangles over
bounding boxes identified by detectors.
"""

from __future__ import annotations

import logging
from io import BytesIO
from pathlib import Path

import cv2
import numpy as np
from PIL import Image

from app.models.findings import EntityType, Finding, RedactionStyle

logger = logging.getLogger(__name__)

# Map common extensions to Pillow-compatible format names.
_EXT_TO_FORMAT: dict[str, str] = {
    ".jpg": "JPEG",
    ".jpeg": "JPEG",
    ".png": "PNG",
}

# Default output format when the extension is not recognised.
_DEFAULT_FORMAT = "PNG"


class ImageSanitizer:
    """Redact PII regions from raster images (JPEG, PNG).

    Implements the ``Sanitizer`` protocol.

    Uses OpenCV to draw filled black rectangles over each finding's
    bounding box, then encodes the result back to the same image
    format as the input.
    """

    def sanitize(
        self,
        file_content: bytes,
        findings: list[Finding],
        filename: str,
        *,
        style: RedactionStyle = RedactionStyle.BLACK,
    ) -> bytes:
        """Black out detected PII regions and return the sanitized image.

        Args:
            file_content: Original image bytes (JPEG or PNG).
            findings: PII detections with optional ``bbox``.
            filename: Original filename — used to determine output format.

        Returns:
            Sanitized image bytes in the same format as the input.
        """
        # Decode image into a NumPy array (BGR colour space).
        buf = np.frombuffer(file_content, dtype=np.uint8)
        mat = cv2.imdecode(buf, cv2.IMREAD_COLOR)

        if mat is None:
            logger.error("Could not decode image '%s' — returning original bytes", filename)
            return file_content

        redaction_count = 0

        for finding in findings:
            if finding.bbox is None:
                logger.debug(
                    "Skipping finding without bbox: %s (score=%.2f)",
                    finding.entity_type.value,
                    finding.score,
                )
                continue

            # Convert BBox coordinates to integer pixel positions.
            x0 = int(round(finding.bbox.x0))
            y0 = int(round(finding.bbox.y0))
            x1 = int(round(finding.bbox.x1))
            y1 = int(round(finding.bbox.y1))

            # Determine per-finding effective style.
            effective_style = style
            if (
                effective_style == RedactionStyle.PLACEHOLDER
                and finding.entity_type in (EntityType.FACE, EntityType.SIGNATURE)
            ):
                effective_style = RedactionStyle.BLACK

            if effective_style == RedactionStyle.BLUR:
                roi_h = y1 - y0
                roi_w = x1 - x0
                if roi_h >= 10 and roi_w >= 10:
                    roi = mat[y0:y1, x0:x1]
                    if roi.size > 0:
                        blurred = cv2.GaussianBlur(roi, (51, 51), 30)
                        mat[y0:y1, x0:x1] = blurred
                else:
                    # ROI too small for blur — fall back to black
                    cv2.rectangle(mat, (x0, y0), (x1, y1), color=(0, 0, 0), thickness=-1)
            elif effective_style == RedactionStyle.PLACEHOLDER:
                cv2.rectangle(mat, (x0, y0), (x1, y1), color=(200, 200, 200), thickness=-1)
                label = f"[{finding.entity_type.value}]"
                box_w = x1 - x0
                font_scale = max(0.3, min(box_w / (len(label) * 15), 1.5))
                cv2.putText(
                    mat, label, (x0 + 4, (y0 + y1) // 2 + 5),
                    cv2.FONT_HERSHEY_SIMPLEX, font_scale, (0, 0, 0), 2,
                )
            else:
                # BLACK (default)
                cv2.rectangle(mat, (x0, y0), (x1, y1), color=(0, 0, 0), thickness=-1)

            redaction_count += 1

        logger.info(
            "%s: blacked out %d region(s) across %d finding(s)",
            filename,
            redaction_count,
            len(findings),
        )

        # Encode back to the original image format.
        output_format = self._resolve_format(filename)
        return self._encode(mat, output_format)

    # ── Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _resolve_format(filename: str) -> str:
        """Determine the Pillow format name from the file extension."""
        ext = Path(filename).suffix.lower()
        return _EXT_TO_FORMAT.get(ext, _DEFAULT_FORMAT)

    @staticmethod
    def _encode(mat: np.ndarray, fmt: str) -> bytes:
        """Encode a BGR OpenCV matrix to image bytes using Pillow.

        We convert from OpenCV BGR to RGB, then use Pillow for encoding
        since it produces better JPEG quality and handles PNG metadata
        more cleanly than ``cv2.imencode``.
        """
        rgb = cv2.cvtColor(mat, cv2.COLOR_BGR2RGB)
        pil_image = Image.fromarray(rgb)

        buffer = BytesIO()
        save_kwargs: dict = {}
        if fmt == "JPEG":
            save_kwargs["quality"] = 95
        pil_image.save(buffer, format=fmt, **save_kwargs)

        return buffer.getvalue()
