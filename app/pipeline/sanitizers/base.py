"""Base protocol for document/image sanitizers."""

from __future__ import annotations

from typing import Protocol

from app.models.findings import Finding


class Sanitizer(Protocol):
    """Structural typing protocol for all sanitizers.

    Implementations receive the original file bytes, a list of findings
    with location information, and the original filename.  They return
    the sanitized file as bytes with PII regions permanently removed or
    obscured.
    """

    def sanitize(
        self,
        file_content: bytes,
        findings: list[Finding],
        filename: str,
    ) -> bytes:
        """Apply redactions to *file_content* and return sanitized bytes.

        Args:
            file_content: Raw bytes of the original uploaded file.
            findings: PII detections — each may carry ``page`` and ``bbox``.
            filename: Original filename (may inform format decisions).

        Returns:
            Sanitized file bytes with PII regions permanently redacted.
        """
        ...
