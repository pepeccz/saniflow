"""PDF sanitizer using PyMuPDF real redaction.

Applies ``add_redact_annot()`` + ``apply_redactions()`` per finding,
which permanently removes text and graphics under the redaction area.
"""

from __future__ import annotations

import logging

import fitz  # PyMuPDF

from app.models.findings import EntityType, Finding, RedactionStyle

logger = logging.getLogger(__name__)


class PdfSanitizer:
    """Redact PII regions from PDF files using PyMuPDF.

    Implements the ``Sanitizer`` protocol.

    For each Finding that has both a ``page`` number and a ``bbox``,
    a redaction annotation is placed on the corresponding page.  Findings
    without coordinate information (text-only detections) are skipped
    since there is no reliable way to locate them on the page.
    """

    def sanitize(
        self,
        file_content: bytes,
        findings: list[Finding],
        filename: str,
        *,
        style: RedactionStyle = RedactionStyle.BLACK,
    ) -> bytes:
        """Open the PDF, add redaction annotations, apply them, and return bytes.

        Args:
            file_content: Original PDF bytes.
            findings: PII detections with optional ``page`` and ``bbox``.
            filename: Original filename (used for logging).

        Returns:
            Sanitized PDF bytes with PII content permanently removed.
        """
        doc = fitz.open(stream=file_content, filetype="pdf")
        page_count = len(doc)
        redaction_count = 0

        # BLUR is not supported for PDFs — fall back to BLACK once.
        effective_base_style = style
        if effective_base_style == RedactionStyle.BLUR:
            logger.warning("BLUR not supported for PDFs — falling back to BLACK")
            effective_base_style = RedactionStyle.BLACK

        for finding in findings:
            if finding.page is None or finding.bbox is None:
                logger.debug(
                    "Skipping finding without coordinates: %s (score=%.2f)",
                    finding.entity_type.value,
                    finding.score,
                )
                continue

            if finding.page < 0 or finding.page >= page_count:
                logger.warning(
                    "Finding references page %d but document has %d pages — skipping",
                    finding.page,
                    page_count,
                )
                continue

            page = doc[finding.page]

            # Convert our BBox model to a PyMuPDF Rect.
            rect = fitz.Rect(
                finding.bbox.x0,
                finding.bbox.y0,
                finding.bbox.x1,
                finding.bbox.y1,
            )

            # Determine per-finding effective style.
            effective_style = effective_base_style
            if (
                effective_style == RedactionStyle.PLACEHOLDER
                and finding.entity_type in (EntityType.FACE, EntityType.SIGNATURE)
            ):
                effective_style = RedactionStyle.BLACK

            if effective_style == RedactionStyle.PLACEHOLDER:
                text = f"[{finding.entity_type.value}]"
                page.add_redact_annot(rect, text=text, fill=(1, 1, 1), text_color=(0, 0, 0))
            else:
                page.add_redact_annot(rect, fill=(0, 0, 0))

            redaction_count += 1

        # Apply all redaction annotations — this PERMANENTLY removes
        # content underneath the redaction areas.
        if redaction_count > 0:
            for page_idx in range(page_count):
                page = doc[page_idx]
                page.apply_redactions()

        logger.info(
            "%s: applied %d redaction(s) across %d finding(s)",
            filename,
            redaction_count,
            len(findings),
        )

        sanitized_bytes = doc.tobytes(deflate=True)
        doc.close()

        return sanitized_bytes
