"""Structured data extractors (JSON, HTML).

Provides ``JsonExtractor`` which recursively flattens JSON into key-path
text lines for PII detection, and ``HtmlExtractor`` which strips markup to
extract visible text for PII scanning.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from app.models.extraction import ExtractionResult, SpanMap

if TYPE_CHECKING:
    import bs4


def _require_bs4() -> type[bs4.BeautifulSoup]:
    """Import and return ``BeautifulSoup``, raising a clear error if missing."""
    try:
        from bs4 import BeautifulSoup  # noqa: WPS433
    except ImportError:
        msg = (
            "beautifulsoup4 is required for HTML support. "
            "Install it with: pip install 'saniflow[structured]'"
        )
        raise RuntimeError(msg) from None
    return BeautifulSoup


class JsonExtractor:
    """Extract text content from JSON files by recursive flattening.

    Produces ``"key.path: value\n"`` for every string value found in the
    JSON structure.  Non-string leaf values (numbers, booleans, null) are
    skipped as they are unlikely to contain PII.

    Implements the ``Extractor`` protocol.
    """

    def extract(self, file_content: bytes, filename: str) -> ExtractionResult:
        """Parse *file_content* as JSON and flatten string values.

        Args:
            file_content: Raw bytes of the JSON file (UTF-8).
            filename: Original filename (unused beyond protocol compliance).

        Returns:
            An ``ExtractionResult`` with flattened text, an empty SpanMap,
            no images, ``pages=1``, and ``is_scanned=False``.
        """
        text_content = file_content.decode("utf-8", errors="replace")

        if not text_content.strip():
            return ExtractionResult(
                text="",
                span_map=SpanMap(),
                images=[],
                pages=1,
                is_scanned=False,
            )

        data = json.loads(text_content)
        lines: list[str] = []
        self._flatten(data, "", lines)

        return ExtractionResult(
            text="".join(lines),
            span_map=SpanMap(),
            images=[],
            pages=1,
            is_scanned=False,
        )

    # ── Helpers ───────────────────────────────────────────────────────

    def _flatten(self, obj: Any, prefix: str, lines: list[str]) -> None:
        """Recursively flatten *obj* into ``"key.path: value\n"`` lines.

        Arrays use numeric indices: ``"users.0.name: Juan\n"``.
        Only string leaf values are emitted; numbers, booleans, and null
        are silently skipped.
        """
        if isinstance(obj, dict):
            for key, value in obj.items():
                new_prefix = f"{prefix}.{key}" if prefix else key
                self._flatten(value, new_prefix, lines)
        elif isinstance(obj, list):
            for index, item in enumerate(obj):
                new_prefix = f"{prefix}.{index}" if prefix else str(index)
                self._flatten(item, new_prefix, lines)
        elif isinstance(obj, str):
            lines.append(f"{prefix}: {obj}\n")
        # Skip int, float, bool, None — no PII expected.


class HtmlExtractor:
    """Extract visible text from HTML files for PII detection.

    Parses the HTML with BeautifulSoup, removes ``<script>`` and ``<style>``
    tags, and returns the remaining visible text.

    Implements the ``Extractor`` protocol.
    """

    def extract(self, file_content: bytes, filename: str) -> ExtractionResult:
        """Parse *file_content* as HTML and extract visible text.

        Args:
            file_content: Raw bytes of the HTML file.
            filename: Original filename (unused beyond protocol compliance).

        Returns:
            An ``ExtractionResult`` with visible text, an empty SpanMap,
            no images, ``pages=1``, and ``is_scanned=False``.
        """
        BeautifulSoup = _require_bs4()
        text_content = file_content.decode("utf-8", errors="replace")

        if not text_content.strip():
            return ExtractionResult(
                text="",
                span_map=SpanMap(),
                images=[],
                pages=1,
                is_scanned=False,
            )

        soup = BeautifulSoup(text_content, "html.parser")

        # Remove non-visible elements before text extraction.
        for tag in soup.find_all(["script", "style"]):
            tag.decompose()

        visible_text = soup.get_text(separator="\n", strip=True)

        return ExtractionResult(
            text=visible_text,
            span_map=SpanMap(),
            images=[],
            pages=1,
            is_scanned=False,
        )
