"""Image extractor using pytesseract OCR.

Extracts text with word-level bounding boxes from JPEG/PNG images and builds
a SpanMap for Presidio offset resolution.
"""

from __future__ import annotations

import logging
from io import BytesIO

import cv2
import numpy as np
import pytesseract
from PIL import Image

from app.config import settings
from app.models.extraction import (
    ExtractionResult,
    ExtractedImage,
    SpanInfo,
    SpanMap,
)

logger = logging.getLogger(__name__)


def _enhance_for_ocr(img: Image.Image) -> Image.Image:
    """Light enhancement for OCR — convert to grayscale only.

    Previous aggressive CLAHE + unsharp-mask sharpening destroyed text
    legibility on phone-camera photos of documents (e.g. DNI cards).
    Tesseract performs its own internal binarisation, so heavy
    preprocessing is counter-productive for most real-world inputs.
    """
    arr = np.array(img.convert("RGB"))
    gray = cv2.cvtColor(arr, cv2.COLOR_RGB2GRAY) if len(arr.shape) == 3 else arr

    return Image.fromarray(gray)


class ImageExtractor:
    """Extract text + coordinates from raster images via OCR.

    Implements the ``Extractor`` protocol.
    """

    def extract(self, file_content: bytes, filename: str) -> ExtractionResult:
        """Run pytesseract ``image_to_data`` on *file_content* and build a SpanMap."""
        image = Image.open(BytesIO(file_content))

        # Enhance image for better OCR (grayscale + CLAHE + sharpening).
        # The original file_content bytes are preserved for visual detection.
        ocr_image = _enhance_for_ocr(image)

        # pytesseract.image_to_data returns a TSV-like structure with columns:
        #   level, page_num, block_num, par_num, line_num, word_num,
        #   left, top, width, height, conf, text
        data = pytesseract.image_to_data(
            ocr_image,
            lang=settings.TESSERACT_LANG,
            output_type=pytesseract.Output.DICT,
        )

        span_map = SpanMap()
        text_parts: list[str] = []

        n_words = len(data["text"])
        prev_block: int = -1
        prev_line: int = -1

        for i in range(n_words):
            word: str = data["text"][i]
            conf: int = int(data["conf"][i])

            # Skip empty entries and very-low-confidence noise.
            if conf < 0 or not word.strip():
                continue

            block_num: int = data["block_num"][i]
            line_num: int = data["line_num"][i]

            # Insert separators when the block or line changes.
            if prev_block >= 0:
                if block_num != prev_block:
                    # New block → double newline.
                    span_map.advance(2)
                    text_parts.append("\n\n")
                elif line_num != prev_line:
                    # Same block, new line → single newline.
                    span_map.advance(1)
                    text_parts.append("\n")
                else:
                    # Same line → space between words.
                    span_map.advance(1)
                    text_parts.append(" ")

            prev_block = block_num
            prev_line = line_num

            left = float(data["left"][i])
            top = float(data["top"][i])
            width = float(data["width"][i])
            height = float(data["height"][i])

            bbox = (left, top, left + width, top + height)
            info = SpanInfo(text=word, bbox=bbox, page=0)

            span_map.append(info)
            text_parts.append(word)

        full_text = "".join(text_parts)

        # The image itself is an ExtractedImage (for visual PII detection).
        images = [
            ExtractedImage(
                content=file_content,
                page=0,
                bbox=None,
            ),
        ]

        return ExtractionResult(
            text=full_text,
            span_map=span_map,
            images=images,
            pages=1,
            is_scanned=True,
        )
