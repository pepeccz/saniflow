"""Pipeline orchestrator — chains extraction, detection, and sanitization.

Resolves file type at runtime via a format registry and selects the
appropriate extractor and sanitizer implementations.  Runs text PII
detection on every file, and visual detection only when the sanitization
level is ``strict``.
"""

from __future__ import annotations

import logging
import mimetypes
from dataclasses import dataclass
from pathlib import Path

from app.models.findings import (
    Finding,
    FindingSummary,
    RedactionStyle,
    ResponseFormat,
    SanitizationLevel,
    SanitizationResult,
)
from app.config import settings
from app.pipeline.preprocessing import extract_document_region, normalize_image
from app.pipeline.detectors.text_pii import TextPiiDetector
from app.pipeline.detectors.visual import VisualDetector
from app.pipeline.extractors.image import ImageExtractor
from app.pipeline.extractors.pdf import PdfExtractor
from app.pipeline.extractors.text import TextExtractor
from app.pipeline.sanitizers.image import ImageSanitizer
from app.pipeline.sanitizers.pdf import PdfSanitizer
from app.pipeline.sanitizers.text import TextSanitizer

logger = logging.getLogger(__name__)

# ── Format registry ───────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class FormatHandler:
    """Maps a file format to its extractor and sanitizer implementations."""

    extractor_cls: type
    sanitizer_cls: type
    category: str  # "pdf", "image", "text"


FORMAT_REGISTRY: dict[str, FormatHandler] = {
    # PDF
    "application/pdf": FormatHandler(PdfExtractor, PdfSanitizer, "pdf"),
    # Images
    "image/jpeg": FormatHandler(ImageExtractor, ImageSanitizer, "image"),
    "image/png": FormatHandler(ImageExtractor, ImageSanitizer, "image"),
    "image/tiff": FormatHandler(ImageExtractor, ImageSanitizer, "image"),
    "image/bmp": FormatHandler(ImageExtractor, ImageSanitizer, "image"),
    "image/webp": FormatHandler(ImageExtractor, ImageSanitizer, "image"),
    # Text
    "text/plain": FormatHandler(TextExtractor, TextSanitizer, "text"),
    "text/markdown": FormatHandler(TextExtractor, TextSanitizer, "text"),
}

# PDF magic bytes: "%PDF"
_PDF_MAGIC = b"%PDF"


def _resolve_content_type(
    file_content: bytes,
    filename: str,
    content_type: str | None = None,
) -> str:
    """Resolve MIME type from explicit value, filename, or magic bytes.

    Raises ``ValueError`` for unsupported formats.
    """
    if content_type and content_type in FORMAT_REGISTRY:
        return content_type

    guessed, _ = mimetypes.guess_type(filename)
    if guessed and guessed in FORMAT_REGISTRY:
        return guessed

    # Fallback: PDF magic bytes.
    if file_content[:4] == _PDF_MAGIC:
        return "application/pdf"

    raise ValueError(f"Unsupported file format: {filename} (content_type={content_type})")


class SanitizationPipeline:
    """Orchestrates the full sanitization pipeline.

    1. Resolve file type via the format registry.
    2. Extract text + images with the appropriate extractor.
    3. Run text PII detection (always).
    4. Run visual PII detection (faces + signatures) if level is strict.
    5. Combine all findings.
    6. Sanitize the file with the appropriate sanitizer.
    7. Build and return a ``SanitizationResult``.
    """

    def __init__(self) -> None:
        # Detectors
        self._text_detector = TextPiiDetector()
        self._visual_detector = VisualDetector()

        # Lazy instance cache for extractors/sanitizers
        self._instance_cache: dict[type, object] = {}

    def _get_instance(self, cls: type) -> object:
        """Return a cached instance of *cls*, creating one if needed."""
        if cls not in self._instance_cache:
            self._instance_cache[cls] = cls()
        return self._instance_cache[cls]

    def process(
        self,
        file_content: bytes,
        filename: str,
        level: SanitizationLevel = SanitizationLevel.STANDARD,
        response_format: ResponseFormat = ResponseFormat.FILE,
        redaction_style: RedactionStyle = RedactionStyle.BLACK,
        redact_entities: list[str] | None = None,
        content_type: str | None = None,
    ) -> SanitizationResult:
        """Run the full sanitization pipeline on *file_content*.

        Args:
            file_content: Raw bytes of the uploaded file.
            filename: Original filename (used for type resolution and output naming).
            level: ``standard`` (text PII only) or ``strict`` (text + visual PII).
            response_format: Controls what the API returns. The pipeline always
                produces findings and sanitized bytes; the API layer decides
                what to include in the response based on this value.
            content_type: Optional explicit MIME type (e.g. from the upload).

        Returns:
            A ``SanitizationResult`` with findings, summary, and sanitized content.
        """
        ct = _resolve_content_type(file_content, filename, content_type)
        handler = FORMAT_REGISTRY[ct]
        logger.info(
            "Processing '%s' as %s (category=%s, level=%s)",
            filename, ct, handler.category, level.value,
        )

        # ── Step 0: Preprocess ─────────────────────────────────────────
        if handler.category == "image":
            if settings.DOCUMENT_EXTRACTION_ENABLED:
                file_content = extract_document_region(file_content, filename)
            file_content = normalize_image(file_content, filename)

        # ── Step 1: Extract ───────────────────────────────────────────
        extractor = self._get_instance(handler.extractor_cls)
        extraction_result = extractor.extract(file_content, filename)

        logger.info(
            "Extraction complete: %d pages, %d chars, %d images, scanned=%s",
            extraction_result.pages,
            len(extraction_result.text),
            len(extraction_result.images),
            extraction_result.is_scanned,
        )

        # ── Step 2: Detect ────────────────────────────────────────────
        findings: list[Finding] = []

        # Always run text PII detection.
        text_findings = self._text_detector.detect(extraction_result, level)
        findings.extend(text_findings)

        # Run visual detection only in strict mode.
        if level == SanitizationLevel.STRICT:
            visual_findings = self._visual_detector.detect(extraction_result, level)
            findings.extend(visual_findings)

        logger.info(
            "Detection complete: %d text findings, %d visual findings",
            len(text_findings),
            len(findings) - len(text_findings),
        )

        # ── Step 2.5: Filter entities ─────────────────────────────────
        if redact_entities:
            redact_set = set(redact_entities)
            for f in findings:
                f.redacted = f.entity_type.value in redact_set
        else:
            for f in findings:
                f.redacted = True

        findings_to_redact = [f for f in findings if f.redacted]

        # ── Step 3: Sanitize ──────────────────────────────────────────
        sanitizer = self._get_instance(handler.sanitizer_cls)
        sanitized_bytes = sanitizer.sanitize(
            file_content, findings_to_redact, filename, style=redaction_style,
        )

        # ── Step 4: Build result ──────────────────────────────────────
        summary = self._build_summary(findings, level)
        output_filename = self._build_output_filename(filename)

        # Include sanitized content unless the caller only wants JSON metadata.
        sanitized_content: bytes | None = None
        if response_format != ResponseFormat.JSON:
            sanitized_content = sanitized_bytes

        result = SanitizationResult(
            findings=findings,
            summary=summary,
            sanitized_content=sanitized_content,
            original_filename=filename,
            output_filename=output_filename,
        )

        logger.info(
            "Pipeline complete for '%s': %d findings, output=%s",
            filename,
            summary.total_findings,
            output_filename,
        )

        return result

    # ── Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _build_summary(
        findings: list[Finding],
        level: SanitizationLevel,
    ) -> FindingSummary:
        """Aggregate findings into a summary."""
        by_type: dict[str, int] = {}
        for finding in findings:
            key = finding.entity_type.value
            by_type[key] = by_type.get(key, 0) + 1

        return FindingSummary(
            total_findings=len(findings),
            by_type=by_type,
            level_applied=level,
        )

    @staticmethod
    def _build_output_filename(filename: str) -> str:
        """Generate the output filename by adding a ``_sanitized`` suffix."""
        path = Path(filename)
        return f"{path.stem}_sanitized{path.suffix}"
