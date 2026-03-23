"""Plain text extractor.

Decodes raw bytes as UTF-8 and wraps the result in an ``ExtractionResult``
with an empty ``SpanMap`` (no coordinate-based redaction for text files).
"""

from __future__ import annotations

from app.models.extraction import ExtractionResult, SpanMap


class TextExtractor:
    """Extract text content from plain text / markdown files.

    Implements the ``Extractor`` protocol.
    """

    def extract(self, file_content: bytes, filename: str) -> ExtractionResult:
        """Decode *file_content* as UTF-8 and return an ``ExtractionResult``.

        Args:
            file_content: Raw bytes of the text file.
            filename: Original filename (unused beyond protocol compliance).

        Returns:
            An ``ExtractionResult`` with the decoded text, an empty SpanMap,
            no images, ``pages=1``, and ``is_scanned=False``.
        """
        text = file_content.decode("utf-8", errors="replace")
        return ExtractionResult(
            text=text,
            span_map=SpanMap(),
            images=[],
            pages=1,
            is_scanned=False,
        )
