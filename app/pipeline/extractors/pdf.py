"""PDF extractor using PyMuPDF (fitz).

Extracts native text with full span-level bounding boxes, builds a SpanMap
for Presidio offset resolution, and falls back to OCR for scanned pages.
"""

from __future__ import annotations

import logging

import fitz  # PyMuPDF

from app.config import settings
from app.models.extraction import (
    ExtractionResult,
    ExtractedImage,
    SpanInfo,
    SpanMap,
)

logger = logging.getLogger(__name__)

# If a page yields fewer than this many characters of native text on average,
# we treat the document as scanned and re-extract with OCR.
_MIN_CHARS_PER_PAGE = 10


class PdfExtractor:
    """Extract text + coordinates from PDF files.

    Implements the ``Extractor`` protocol.
    """

    # ------------------------------------------------------------------
    # Public API (Extractor protocol)
    # ------------------------------------------------------------------

    def extract(self, file_content: bytes, filename: str) -> ExtractionResult:
        """Open *file_content* as a PDF and produce an ``ExtractionResult``."""
        doc = fitz.open(stream=file_content, filetype="pdf")
        page_count = len(doc)

        span_map = SpanMap()
        text_parts: list[str] = []
        images: list[ExtractedImage] = []

        # --- First pass: native text ---
        for page_idx in range(page_count):
            page = doc[page_idx]
            page_text = self._extract_page_native(page, page_idx, span_map, text_parts)

        full_text = "".join(text_parts)

        # --- Scanned-document detection ---
        avg_chars = len(full_text.strip()) / max(page_count, 1)
        is_scanned = avg_chars < _MIN_CHARS_PER_PAGE

        if is_scanned:
            logger.info(
                "%s: avg %.1f chars/page — falling back to OCR",
                filename,
                avg_chars,
            )
            span_map = SpanMap()
            text_parts = []
            for page_idx in range(page_count):
                page = doc[page_idx]
                self._extract_page_ocr(page, page_idx, span_map, text_parts)
            full_text = "".join(text_parts)

        # --- Extract embedded images (for visual PII detection) ---
        for page_idx in range(page_count):
            page = doc[page_idx]
            page_images = self._extract_images(page, page_idx, doc)
            images.extend(page_images)

        doc.close()

        return ExtractionResult(
            text=full_text,
            span_map=span_map,
            images=images,
            pages=page_count,
            is_scanned=is_scanned,
        )

    # ------------------------------------------------------------------
    # Native text extraction
    # ------------------------------------------------------------------

    def _extract_page_native(
        self,
        page: fitz.Page,
        page_idx: int,
        span_map: SpanMap,
        text_parts: list[str],
    ) -> str:
        """Walk ``get_text("dict")`` blocks→lines→spans and populate *span_map*.

        Appends text to *text_parts* and returns the page's text contribution.
        Reading order is preserved as provided by PyMuPDF (top-to-bottom,
        left-to-right within each block).
        """
        text_dict = page.get_text("dict", flags=fitz.TEXT_PRESERVE_WHITESPACE)
        page_text_parts: list[str] = []

        for block in text_dict.get("blocks", []):
            # Skip image blocks (type 1).
            if block.get("type", 0) != 0:
                continue

            for line_idx, line in enumerate(block.get("lines", [])):
                for span_idx, span in enumerate(line.get("spans", [])):
                    span_text: str = span.get("text", "")
                    if not span_text:
                        continue

                    bbox = (
                        float(span["bbox"][0]),
                        float(span["bbox"][1]),
                        float(span["bbox"][2]),
                        float(span["bbox"][3]),
                    )
                    info = SpanInfo(text=span_text, bbox=bbox, page=page_idx)
                    span_map.append(info)
                    page_text_parts.append(span_text)
                    text_parts.append(span_text)

                    # Add a space between spans within the same line
                    # (unless the span already ends with whitespace).
                    if span_idx < len(line["spans"]) - 1 and not span_text.endswith((" ", "\t")):
                        span_map.advance(1)
                        text_parts.append(" ")
                        page_text_parts.append(" ")

                # Newline between lines within the same block.
                if line_idx < len(block["lines"]) - 1:
                    span_map.advance(1)
                    text_parts.append("\n")
                    page_text_parts.append("\n")

            # Newline between blocks.
            span_map.advance(1)
            text_parts.append("\n")
            page_text_parts.append("\n")

        # Extra newline between pages.
        span_map.advance(1)
        text_parts.append("\n")
        page_text_parts.append("\n")

        # Validate SpanMap stays in sync with assembled text.
        assembled_len = sum(len(p) for p in text_parts)
        assert span_map.cursor == assembled_len, (
            f"SpanMap drift on page {page_idx}: "
            f"cursor={span_map.cursor}, text_len={assembled_len}"
        )

        return "".join(page_text_parts)

    # ------------------------------------------------------------------
    # OCR fallback
    # ------------------------------------------------------------------

    def _extract_page_ocr(
        self,
        page: fitz.Page,
        page_idx: int,
        span_map: SpanMap,
        text_parts: list[str],
    ) -> None:
        """Use PyMuPDF's built-in Tesseract OCR to extract text with positions.

        ``get_textpage_ocr`` creates a TextPage with OCR results, then we
        use ``extractDICT`` on that TextPage to get the same
        blocks→lines→spans structure as native extraction.
        """
        tp = page.get_textpage_ocr(
            language=settings.TESSERACT_LANG,
            dpi=72,
            full=True,
        )
        text_dict = tp.extractDICT()

        for block in text_dict.get("blocks", []):
            if block.get("type", 0) != 0:
                continue

            for line_idx, line in enumerate(block.get("lines", [])):
                for span_idx, span in enumerate(line.get("spans", [])):
                    span_text: str = span.get("text", "")
                    if not span_text:
                        continue

                    bbox = (
                        float(span["bbox"][0]),
                        float(span["bbox"][1]),
                        float(span["bbox"][2]),
                        float(span["bbox"][3]),
                    )
                    info = SpanInfo(text=span_text, bbox=bbox, page=page_idx)
                    span_map.append(info)
                    text_parts.append(span_text)

                    if span_idx < len(line["spans"]) - 1 and not span_text.endswith((" ", "\t")):
                        span_map.advance(1)
                        text_parts.append(" ")

                if line_idx < len(block["lines"]) - 1:
                    span_map.advance(1)
                    text_parts.append("\n")

            span_map.advance(1)
            text_parts.append("\n")

        span_map.advance(1)
        text_parts.append("\n")

        # Validate SpanMap stays in sync with assembled text (OCR path).
        assembled_len = sum(len(p) for p in text_parts)
        assert span_map.cursor == assembled_len, (
            f"SpanMap drift (OCR) on page {page_idx}: "
            f"cursor={span_map.cursor}, text_len={assembled_len}"
        )

    # ------------------------------------------------------------------
    # Image extraction
    # ------------------------------------------------------------------

    def _extract_images(
        self,
        page: fitz.Page,
        page_idx: int,
        doc: fitz.Document,
    ) -> list[ExtractedImage]:
        """Extract embedded images from *page* for visual PII detection."""
        extracted: list[ExtractedImage] = []

        for img_info in page.get_images(full=True):
            xref = img_info[0]
            try:
                base_image = doc.extract_image(xref)
            except Exception:
                logger.debug("Could not extract image xref=%d on page %d", xref, page_idx)
                continue

            if not base_image or not base_image.get("image"):
                continue

            # Try to get the bbox of the image on the page.
            bbox: tuple[float, float, float, float] | None = None
            for img_rect_info in page.get_image_rects(xref):
                bbox = (
                    float(img_rect_info.x0),
                    float(img_rect_info.y0),
                    float(img_rect_info.x1),
                    float(img_rect_info.y1),
                )
                break  # Take the first placement.

            extracted.append(
                ExtractedImage(
                    content=base_image["image"],
                    page=page_idx,
                    bbox=bbox,
                )
            )

        return extracted
