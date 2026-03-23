"""Plain text sanitizer.

Replaces PII spans in plain text using string replacement based on
``Finding.original_text``.  Processes findings in reverse position order
to avoid index shifting during replacement.
"""

from __future__ import annotations

import logging

from app.models.findings import Finding, RedactionStyle

logger = logging.getLogger(__name__)


class TextSanitizer:
    """Redact PII in plain text / markdown files.

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
        """Replace PII text with redaction markers and return sanitized bytes.

        Args:
            file_content: Original text file bytes (UTF-8).
            findings: PII detections with ``original_text`` populated.
            filename: Original filename (for logging).
            style: Redaction style — ``BLACK`` uses block characters,
                ``PLACEHOLDER`` / ``BLUR`` use ``[ENTITY_TYPE]`` labels.

        Returns:
            Sanitized text file bytes (UTF-8).
        """
        text = file_content.decode("utf-8", errors="replace")
        sorted_findings = self._sort_findings_by_position(text, findings)

        redaction_count = 0
        for finding in sorted_findings:
            if not finding.original_text:
                continue

            pos = text.rfind(finding.original_text)
            if pos == -1:
                continue

            replacement = self._get_replacement(finding, style)
            text = text[:pos] + replacement + text[pos + len(finding.original_text):]
            redaction_count += 1

        logger.info(
            "%s: redacted %d region(s) across %d finding(s)",
            filename,
            redaction_count,
            len(findings),
        )

        return text.encode("utf-8")

    # ── Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _get_replacement(finding: Finding, style: RedactionStyle) -> str:
        """Build the replacement string for a given finding and style."""
        if style in (RedactionStyle.PLACEHOLDER, RedactionStyle.BLUR):
            return f"[{finding.entity_type.value}]"
        # BLACK (default): unicode block characters matching original length.
        return "\u2588" * len(finding.original_text)

    @staticmethod
    def _sort_findings_by_position(
        text: str,
        findings: list[Finding],
    ) -> list[Finding]:
        """Sort findings by their position in *text*, last occurrence first."""

        def find_pos(f: Finding) -> int:
            if f.original_text:
                pos = text.find(f.original_text)
                return pos if pos >= 0 else len(text)
            return len(text)

        return sorted(findings, key=find_pos, reverse=True)
