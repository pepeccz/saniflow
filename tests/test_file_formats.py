"""Tests for file format expansion: registry, image formats, and plain text support."""

from __future__ import annotations

from io import BytesIO
from unittest.mock import MagicMock

import pytest
from PIL import Image

from app.models.extraction import ExtractionResult, SpanMap
from app.models.findings import (
    EntityType,
    Finding,
    RedactionStyle,
    SanitizationLevel,
)
from app.pipeline.orchestrator import (
    FORMAT_REGISTRY,
    FormatHandler,
    SanitizationPipeline,
    _resolve_content_type,
)


# ---------------------------------------------------------------------------
# Format registry tests
# ---------------------------------------------------------------------------


class TestFormatRegistry:
    """Verify the registry maps MIME types to the correct handlers."""

    @pytest.mark.parametrize(
        "mime_type,expected_category",
        [
            ("application/pdf", "pdf"),
            ("image/jpeg", "image"),
            ("image/png", "image"),
            ("image/tiff", "image"),
            ("image/bmp", "image"),
            ("image/webp", "image"),
            ("text/plain", "text"),
            ("text/markdown", "text"),
        ],
    )
    def test_registry_has_entry(self, mime_type: str, expected_category: str):
        handler = FORMAT_REGISTRY[mime_type]
        assert isinstance(handler, FormatHandler)
        assert handler.category == expected_category

    def test_image_formats_share_handler_classes(self):
        """All image formats should use the same extractor/sanitizer classes."""
        image_types = [k for k, v in FORMAT_REGISTRY.items() if v.category == "image"]
        assert len(image_types) >= 5  # jpeg, png, tiff, bmp, webp
        classes = {(FORMAT_REGISTRY[t].extractor_cls, FORMAT_REGISTRY[t].sanitizer_cls) for t in image_types}
        assert len(classes) == 1, "All image formats should share the same handler classes"


# ---------------------------------------------------------------------------
# Content type resolution tests
# ---------------------------------------------------------------------------


class TestResolveContentType:
    def test_explicit_content_type_wins(self):
        assert _resolve_content_type(b"anything", "file.xyz", "application/pdf") == "application/pdf"

    def test_filename_extension(self):
        assert _resolve_content_type(b"data", "photo.jpg") == "image/jpeg"

    def test_pdf_magic_fallback(self):
        assert _resolve_content_type(b"%PDF-1.4", "unknown_file") == "application/pdf"

    def test_unsupported_raises(self):
        with pytest.raises(ValueError, match="Unsupported file format"):
            _resolve_content_type(b"random", "file.xyz")

    def test_tiff_extension(self):
        assert _resolve_content_type(b"data", "scan.tiff") == "image/tiff"

    def test_bmp_extension(self):
        assert _resolve_content_type(b"data", "scan.bmp") == "image/bmp"

    def test_webp_extension(self):
        assert _resolve_content_type(b"data", "photo.webp") == "image/webp"

    def test_txt_extension(self):
        assert _resolve_content_type(b"data", "notes.txt") == "text/plain"

    def test_md_extension(self):
        ct = _resolve_content_type(b"data", "readme.md")
        assert ct == "text/markdown"


# ---------------------------------------------------------------------------
# Additional image format tests
# ---------------------------------------------------------------------------


def _make_image_bytes(fmt: str, ext: str) -> bytes:
    """Create a minimal image in the given format."""
    img = Image.new("RGB", (100, 50), color=(255, 255, 255))
    buf = BytesIO()
    img.save(buf, format=fmt)
    return buf.getvalue()


class TestAdditionalImageFormats:
    """Verify TIFF, BMP, WEBP are processed through the image pipeline."""

    @pytest.mark.parametrize(
        "fmt,ext",
        [
            ("TIFF", ".tiff"),
            ("BMP", ".bmp"),
            ("WEBP", ".webp"),
        ],
    )
    def test_image_format_routes_to_image_handler(self, fmt: str, ext: str):
        """Image files should be dispatched to the image extractor/sanitizer."""
        from app.pipeline.extractors.image import ImageExtractor
        from app.pipeline.sanitizers.image import ImageSanitizer

        image_bytes = _make_image_bytes(fmt, ext)

        pipeline = object.__new__(SanitizationPipeline)
        mock_extractor = MagicMock()
        mock_sanitizer = MagicMock()
        pipeline._text_detector = MagicMock()
        pipeline._visual_detector = MagicMock()
        pipeline._instance_cache = {
            ImageExtractor: mock_extractor,
            ImageSanitizer: mock_sanitizer,
        }

        mock_extractor.extract.return_value = ExtractionResult(
            text="", span_map=SpanMap(), images=[], pages=1, is_scanned=False,
        )
        pipeline._text_detector.detect.return_value = []
        pipeline._visual_detector.detect.return_value = []
        mock_sanitizer.sanitize.return_value = image_bytes

        result = pipeline.process(
            file_content=image_bytes,
            filename=f"test{ext}",
            level=SanitizationLevel.STANDARD,
        )

        mock_extractor.extract.assert_called_once()
        mock_sanitizer.sanitize.assert_called_once()
        assert result.output_filename == f"test_sanitized{ext}"

    def test_image_sanitizer_format_resolution(self):
        """ImageSanitizer._resolve_format should handle new extensions."""
        from app.pipeline.sanitizers.image import ImageSanitizer

        sanitizer = ImageSanitizer()
        assert sanitizer._resolve_format("scan.tiff") == "TIFF"
        assert sanitizer._resolve_format("scan.tif") == "TIFF"
        assert sanitizer._resolve_format("photo.bmp") == "BMP"
        assert sanitizer._resolve_format("photo.webp") == "WEBP"


# ---------------------------------------------------------------------------
# Plain text extractor tests
# ---------------------------------------------------------------------------


class TestTextExtractor:
    def test_extract_returns_text(self):
        from app.pipeline.extractors.text import TextExtractor

        extractor = TextExtractor()
        content = "Juan Garcia, DNI: 12345678Z".encode("utf-8")
        result = extractor.extract(content, "test.txt")

        assert result.text == "Juan Garcia, DNI: 12345678Z"
        assert len(result.span_map) == 0
        assert result.images == []
        assert result.pages == 1
        assert result.is_scanned is False

    def test_extract_handles_invalid_utf8(self):
        from app.pipeline.extractors.text import TextExtractor

        extractor = TextExtractor()
        content = b"Hello \xff\xfe World"
        result = extractor.extract(content, "broken.txt")

        assert "Hello" in result.text
        assert "World" in result.text


# ---------------------------------------------------------------------------
# Plain text sanitizer tests
# ---------------------------------------------------------------------------


class TestTextSanitizer:
    def test_black_style_replaces_with_blocks(self):
        from app.pipeline.sanitizers.text import TextSanitizer

        sanitizer = TextSanitizer()
        content = "Mi nombre es Juan Garcia y mi DNI es 12345678Z".encode("utf-8")
        findings = [
            Finding(entity_type=EntityType.PERSON_NAME, original_text="Juan Garcia", score=0.9),
            Finding(entity_type=EntityType.DNI_NIE, original_text="12345678Z", score=0.99),
        ]

        result = sanitizer.sanitize(content, findings, "test.txt", style=RedactionStyle.BLACK)
        text = result.decode("utf-8")

        assert "Juan Garcia" not in text
        assert "12345678Z" not in text
        assert "\u2588" * 11 in text  # len("Juan Garcia") == 11
        assert "\u2588" * 9 in text   # len("12345678Z") == 9

    def test_placeholder_style_replaces_with_labels(self):
        from app.pipeline.sanitizers.text import TextSanitizer

        sanitizer = TextSanitizer()
        content = "Email: juan@example.com".encode("utf-8")
        findings = [
            Finding(entity_type=EntityType.EMAIL, original_text="juan@example.com", score=0.99),
        ]

        result = sanitizer.sanitize(content, findings, "test.txt", style=RedactionStyle.PLACEHOLDER)
        text = result.decode("utf-8")

        assert "juan@example.com" not in text
        assert "[EMAIL]" in text

    def test_blur_style_same_as_placeholder(self):
        from app.pipeline.sanitizers.text import TextSanitizer

        sanitizer = TextSanitizer()
        content = "Tel: +34 612345678".encode("utf-8")
        findings = [
            Finding(entity_type=EntityType.PHONE, original_text="+34 612345678", score=0.9),
        ]

        result = sanitizer.sanitize(content, findings, "test.txt", style=RedactionStyle.BLUR)
        text = result.decode("utf-8")

        assert "+34 612345678" not in text
        assert "[PHONE]" in text

    def test_no_findings_returns_unchanged(self):
        from app.pipeline.sanitizers.text import TextSanitizer

        sanitizer = TextSanitizer()
        content = b"Nothing to redact here."

        result = sanitizer.sanitize(content, [], "test.txt")
        assert result == content

    def test_finding_without_original_text_is_skipped(self):
        from app.pipeline.sanitizers.text import TextSanitizer

        sanitizer = TextSanitizer()
        content = b"Some text content."
        findings = [
            Finding(entity_type=EntityType.FACE, original_text=None, score=0.9),
        ]

        result = sanitizer.sanitize(content, findings, "test.txt")
        assert result == content


# ---------------------------------------------------------------------------
# Text pipeline integration tests
# ---------------------------------------------------------------------------


class TestTextPipelineIntegration:
    """Verify text files flow through the full pipeline correctly."""

    def _make_text_pipeline(self):
        from app.pipeline.extractors.text import TextExtractor
        from app.pipeline.sanitizers.text import TextSanitizer

        pipeline = object.__new__(SanitizationPipeline)
        pipeline._text_detector = MagicMock()
        pipeline._visual_detector = MagicMock()
        pipeline._instance_cache = {
            TextExtractor: TextExtractor(),
            TextSanitizer: TextSanitizer(),
        }
        return pipeline

    def test_text_file_processed_end_to_end(self):
        pipeline = self._make_text_pipeline()
        content = "Juan Garcia, DNI: 12345678Z".encode("utf-8")
        findings = [
            Finding(entity_type=EntityType.PERSON_NAME, original_text="Juan Garcia", score=0.9),
        ]
        pipeline._text_detector.detect.return_value = findings
        pipeline._visual_detector.detect.return_value = []

        result = pipeline.process(
            file_content=content,
            filename="data.txt",
            level=SanitizationLevel.STANDARD,
        )

        assert result.summary.total_findings == 1
        assert result.sanitized_content is not None
        assert b"Juan Garcia" not in result.sanitized_content
        assert result.output_filename == "data_sanitized.txt"

    def test_markdown_file_processed_like_text(self):
        pipeline = self._make_text_pipeline()
        content = "# Title\n\nJuan Garcia wrote this.".encode("utf-8")
        findings = [
            Finding(entity_type=EntityType.PERSON_NAME, original_text="Juan Garcia", score=0.9),
        ]
        pipeline._text_detector.detect.return_value = findings
        pipeline._visual_detector.detect.return_value = []

        result = pipeline.process(
            file_content=content,
            filename="notes.md",
            level=SanitizationLevel.STANDARD,
        )

        assert result.summary.total_findings == 1
        assert result.sanitized_content is not None
        assert b"Juan Garcia" not in result.sanitized_content

    def test_text_skips_preprocessing(self):
        """Text files should NOT run image preprocessing."""
        pipeline = self._make_text_pipeline()
        content = b"Simple text."
        pipeline._text_detector.detect.return_value = []
        pipeline._visual_detector.detect.return_value = []

        # If preprocessing ran on text content, it would likely fail or corrupt.
        # The fact that this passes without error confirms preprocessing is skipped.
        result = pipeline.process(
            file_content=content,
            filename="notes.txt",
            level=SanitizationLevel.STANDARD,
        )

        assert result.sanitized_content == content

    def test_strict_mode_skips_visual_for_empty_images(self):
        """In strict mode, visual detector runs but finds nothing (no images in text)."""
        pipeline = self._make_text_pipeline()
        content = b"Just text, no images."
        pipeline._text_detector.detect.return_value = []
        pipeline._visual_detector.detect.return_value = []

        result = pipeline.process(
            file_content=content,
            filename="notes.txt",
            level=SanitizationLevel.STRICT,
        )

        # Visual detector is still called but should return empty
        pipeline._visual_detector.detect.assert_called_once()
        assert result.summary.total_findings == 0
