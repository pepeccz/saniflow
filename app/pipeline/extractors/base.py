"""Base protocol for document/image extractors."""

from __future__ import annotations

from typing import Protocol

from app.models.extraction import ExtractionResult


class Extractor(Protocol):
    """Structural typing protocol for all extractors.

    Implementations must accept raw file bytes and a filename (used for
    logging / format hints) and return a fully-populated ExtractionResult
    with text, SpanMap, extracted images, etc.
    """

    def extract(self, file_content: bytes, filename: str) -> ExtractionResult:
        """Extract text, coordinates, and embedded images from *file_content*.

        Args:
            file_content: Raw bytes of the uploaded file.
            filename: Original filename (may inform format detection).

        Returns:
            An ``ExtractionResult`` containing the concatenated text,
            the SpanMap for offset→bbox resolution, extracted images,
            page count, and whether OCR was used.
        """
        ...
