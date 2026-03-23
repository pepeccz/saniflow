"""Extraction models: SpanInfo, SpanMap, ExtractionResult, ExtractedImage.

SpanMap is the core mapping structure that links Presidio character offsets
back to page coordinates (bounding boxes). It is built during extraction by
walking PyMuPDF spans or OCR word boxes, tracking cumulative character offsets.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class SpanInfo:
    """A single text span with its position metadata.

    Attributes:
        text: The text content of this span.
        bbox: Bounding box as (x0, y0, x1, y1) in PDF/image coordinates.
        page: Zero-indexed page number.
    """

    text: str
    bbox: tuple[float, float, float, float]
    page: int


@dataclass(slots=True)
class SpanMap:
    """Maps cumulative character offsets to source spans for coordinate resolution.

    Built during extraction by appending spans in reading order. Each entry
    records the cumulative offset where a span's text begins, together with
    the span's metadata (text, bbox, page).

    ``resolve(start, end)`` accepts Presidio-style character offsets into the
    concatenated full text and returns every (page, bbox) pair that overlaps
    with the [start, end) range.  Uses ``bisect`` for O(log n) initial lookup.
    """

    # List of (cumulative_offset, SpanInfo), kept sorted by offset.
    _entries: list[tuple[int, SpanInfo]] = field(default_factory=list)

    # Parallel list of just the offsets — kept in sync with _entries so that
    # bisect can operate on a plain list[int] without key functions.
    _offsets: list[int] = field(default_factory=list)

    # Running character count used while building.
    _cursor: int = field(default=0)

    # --- Building API ---

    def append(self, span_info: SpanInfo) -> int:
        """Register *span_info* at the current cursor position.

        Returns the cursor position where this span starts (i.e. its
        global offset in the concatenated text).
        """
        start = self._cursor
        self._entries.append((start, span_info))
        self._offsets.append(start)
        self._cursor += len(span_info.text)
        return start

    def advance(self, count: int = 1) -> None:
        """Advance the cursor by *count* characters without registering a span.

        Use this to account for separators (spaces, newlines) injected
        between spans during text concatenation.
        """
        self._cursor += count

    @property
    def cursor(self) -> int:
        """Current cumulative character offset."""
        return self._cursor

    def __len__(self) -> int:
        return len(self._entries)

    # --- Resolution API ---

    def resolve(self, start: int, end: int) -> list[tuple[int, tuple[float, float, float, float]]]:
        """Given character offsets ``[start, end)`` from Presidio, return
        overlapping ``(page, bbox)`` pairs.

        The algorithm:
        1. Use ``bisect_right`` on the offsets list to find the rightmost
           entry whose offset is <= *start*.  That is the first candidate.
        2. Walk forward through entries while the entry's offset is < *end*.
        3. For each entry, check whether the span's character range
           ``[entry_offset, entry_offset + len(span.text))`` actually
           overlaps ``[start, end)``.  If so, include it.

        Returns a de-duplicated list of ``(page, bbox)`` tuples (a single
        span won't appear twice, but the same bbox on the same page could
        in theory come from two distinct spans — we keep both).
        """
        if not self._entries:
            return []

        # Find insertion point: bisect_right gives us the index of the first
        # offset that is strictly greater than `start`.  We subtract 1 to get
        # the last offset that is <= `start`.
        idx = bisect.bisect_right(self._offsets, start) - 1
        if idx < 0:
            idx = 0

        results: list[tuple[int, tuple[float, float, float, float]]] = []

        for i in range(idx, len(self._entries)):
            entry_offset, span_info = self._entries[i]

            # If this span starts at or beyond `end`, no more overlaps.
            if entry_offset >= end:
                break

            span_end = entry_offset + len(span_info.text)

            # Check overlap: [entry_offset, span_end) ∩ [start, end) != ∅
            if span_end > start and entry_offset < end:
                results.append((span_info.page, span_info.bbox))

        return results


@dataclass(frozen=True, slots=True)
class ExtractedImage:
    """An image extracted from a document (embedded photo, full page scan, etc.).

    Attributes:
        content: Raw image bytes (PNG/JPEG).
        page: Zero-indexed page the image was found on.
        bbox: Bounding box on the page, or None if the image IS the full page.
    """

    content: bytes
    page: int
    bbox: tuple[float, float, float, float] | None = None


@dataclass(slots=True)
class ExtractionResult:
    """Result of running an Extractor on a file.

    Attributes:
        text: Full concatenated text (what Presidio will analyze).
        span_map: Offset-to-coordinate mapping built during extraction.
        images: Embedded images extracted for visual PII detection.
        pages: Total number of pages in the source document.
        is_scanned: True if OCR was used (no native text found).
    """

    text: str
    span_map: SpanMap
    images: list[ExtractedImage] = field(default_factory=list)
    pages: int = 1
    is_scanned: bool = False
