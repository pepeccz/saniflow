"""Structured data sanitizers (JSON, HTML).

Provides ``JsonSanitizer`` which re-parses original JSON bytes, locates
PII strings within values, and replaces them while preserving the full
JSON structure, and ``HtmlSanitizer`` which redacts PII in HTML text nodes
while preserving the document markup.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from app.models.findings import Finding, RedactionStyle

if TYPE_CHECKING:
    import bs4

logger = logging.getLogger(__name__)


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


class JsonSanitizer:
    """Redact PII in JSON files while preserving structure.

    Re-parses the original JSON, walks all string values, replaces
    occurrences of ``finding.original_text`` with the appropriate
    redaction marker, and re-serializes with readable formatting.

    Implements the ``Sanitizer`` protocol.
    """

    def sanitize(
        self,
        file_content: bytes,
        findings: list[Finding],
        filename: str,
        *,
        style: RedactionStyle = RedactionStyle.BLACK,
    ) -> bytes:
        """Replace PII in JSON string values and return sanitized bytes.

        Args:
            file_content: Original JSON file bytes (UTF-8).
            findings: PII detections with ``original_text`` populated.
            filename: Original filename (for logging).
            style: Redaction style — ``BLACK`` uses block characters,
                ``PLACEHOLDER`` / ``BLUR`` use ``[ENTITY_TYPE]`` labels.

        Returns:
            Sanitized JSON bytes (UTF-8) with ``indent=2`` formatting.
        """
        text_content = file_content.decode("utf-8", errors="replace")

        if not text_content.strip():
            return file_content

        data = json.loads(text_content)

        redaction_count = 0
        for finding in findings:
            if not finding.original_text:
                continue

            replacement = self._get_replacement(finding, style)
            count = self._replace_in_structure(
                data, finding.original_text, replacement,
            )
            redaction_count += count

        logger.info(
            "%s: redacted %d region(s) across %d finding(s)",
            filename,
            redaction_count,
            len(findings),
        )

        output = json.dumps(data, indent=2, ensure_ascii=False)
        return output.encode("utf-8")

    # ── Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _get_replacement(finding: Finding, style: RedactionStyle) -> str:
        """Build the replacement string for a given finding and style."""
        if style in (RedactionStyle.PLACEHOLDER, RedactionStyle.BLUR):
            return f"[{finding.entity_type.value}]"
        # BLACK (default): unicode block characters matching original length.
        return "\u2588" * len(finding.original_text)

    def _replace_in_structure(
        self,
        obj: Any,
        original: str,
        replacement: str,
    ) -> int:
        """Recursively walk *obj* and replace *original* in string values.

        Returns the number of replacements made.
        """
        count = 0

        if isinstance(obj, dict):
            for key in obj:
                if isinstance(obj[key], str) and original in obj[key]:
                    obj[key] = obj[key].replace(original, replacement)
                    count += 1
                elif isinstance(obj[key], (dict, list)):
                    count += self._replace_in_structure(
                        obj[key], original, replacement,
                    )
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                if isinstance(item, str) and original in item:
                    obj[i] = item.replace(original, replacement)
                    count += 1
                elif isinstance(item, (dict, list)):
                    count += self._replace_in_structure(
                        item, original, replacement,
                    )

        return count


class HtmlSanitizer:
    """Redact PII in HTML files while preserving markup structure.

    Parses the HTML with BeautifulSoup, locates text nodes containing
    PII strings, replaces them with the appropriate redaction marker,
    and re-serializes the modified tree.

    Implements the ``Sanitizer`` protocol.
    """

    def sanitize(
        self,
        file_content: bytes,
        findings: list[Finding],
        filename: str,
        *,
        style: RedactionStyle = RedactionStyle.BLACK,
    ) -> bytes:
        """Replace PII in HTML text nodes and return sanitized bytes.

        Args:
            file_content: Original HTML file bytes.
            findings: PII detections with ``original_text`` populated.
            filename: Original filename (for logging).
            style: Redaction style — ``BLACK`` uses block characters,
                ``PLACEHOLDER`` / ``BLUR`` use ``[ENTITY_TYPE]`` labels.

        Returns:
            Sanitized HTML bytes (UTF-8) with markup preserved.
        """
        BeautifulSoup = _require_bs4()
        from bs4 import NavigableString  # noqa: WPS433

        text_content = file_content.decode("utf-8", errors="replace")

        if not text_content.strip():
            return file_content

        soup = BeautifulSoup(text_content, "html.parser")

        redaction_count = 0
        for finding in findings:
            if not finding.original_text:
                continue

            replacement = self._get_replacement(finding, style)
            original_text = finding.original_text

            # Find all text nodes containing the PII text.
            matching_nodes = soup.find_all(
                string=lambda s: original_text in s,  # noqa: B023
            )

            for node in matching_nodes:
                new_text = node.replace(original_text, replacement)
                node.replace_with(NavigableString(new_text))
                redaction_count += 1

        logger.info(
            "%s: redacted %d region(s) across %d finding(s)",
            filename,
            redaction_count,
            len(findings),
        )

        return str(soup).encode("utf-8")

    # ── Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _get_replacement(finding: Finding, style: RedactionStyle) -> str:
        """Build the replacement string for a given finding and style."""
        if style in (RedactionStyle.PLACEHOLDER, RedactionStyle.BLUR):
            return f"[{finding.entity_type.value}]"
        # BLACK (default): unicode block characters matching original length.
        return "\u2588" * len(finding.original_text)
