"""Tests for configurable redaction: RedactionStyle, entity filtering, and pipeline integration."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.models.findings import (
    BBox,
    EntityType,
    Finding,
    RedactionStyle,
    ResponseFormat,
    SanitizationLevel,
)
from app.pipeline.orchestrator import SanitizationPipeline


# ---------------------------------------------------------------------------
# Unit tests: RedactionStyle enum
# ---------------------------------------------------------------------------


class TestRedactionStyleEnum:
    def test_values(self):
        assert RedactionStyle.BLACK.value == "black"
        assert RedactionStyle.BLUR.value == "blur"
        assert RedactionStyle.PLACEHOLDER.value == "placeholder"

    def test_from_string(self):
        assert RedactionStyle("black") == RedactionStyle.BLACK
        assert RedactionStyle("blur") == RedactionStyle.BLUR
        assert RedactionStyle("placeholder") == RedactionStyle.PLACEHOLDER

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            RedactionStyle("invalid")

    def test_is_str_subclass(self):
        assert isinstance(RedactionStyle.BLACK, str)


# ---------------------------------------------------------------------------
# Unit tests: Finding.redacted default
# ---------------------------------------------------------------------------


class TestFindingRedacted:
    def test_default_is_true(self):
        f = Finding(entity_type=EntityType.PERSON_NAME, score=0.9)
        assert f.redacted is True

    def test_can_set_false(self):
        f = Finding(entity_type=EntityType.PERSON_NAME, score=0.9, redacted=False)
        assert f.redacted is False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_findings() -> list[Finding]:
    return [
        Finding(
            entity_type=EntityType.PERSON_NAME,
            original_text="Juan",
            score=0.9,
            page=0,
            bbox=BBox(x0=10, y0=10, x1=100, y1=30),
        ),
        Finding(
            entity_type=EntityType.EMAIL,
            original_text="juan@example.com",
            score=0.99,
            page=0,
            bbox=BBox(x0=110, y0=10, x1=300, y1=30),
        ),
        Finding(
            entity_type=EntityType.DNI_NIE,
            original_text="12345678Z",
            score=0.95,
            page=0,
            bbox=BBox(x0=10, y0=40, x1=120, y1=60),
        ),
    ]


def _make_pipeline_with_mocks(
    text_findings: list[Finding] | None = None,
) -> SanitizationPipeline:
    """Build a pipeline with all components mocked."""
    from app.models.extraction import ExtractionResult, SpanMap
    from app.pipeline.extractors.pdf import PdfExtractor
    from app.pipeline.sanitizers.pdf import PdfSanitizer

    mock_pdf_extractor = MagicMock()
    mock_pdf_sanitizer = MagicMock()

    pipeline = object.__new__(SanitizationPipeline)
    pipeline._text_detector = MagicMock()
    pipeline._visual_detector = MagicMock()
    pipeline._instance_cache = {
        PdfExtractor: mock_pdf_extractor,
        PdfSanitizer: mock_pdf_sanitizer,
    }

    extraction = ExtractionResult(
        text="test", span_map=SpanMap(), images=[], pages=1, is_scanned=False,
    )
    mock_pdf_extractor.extract.return_value = extraction

    pipeline._text_detector.detect.return_value = text_findings or []
    pipeline._visual_detector.detect.return_value = []

    mock_pdf_sanitizer.sanitize.return_value = b"sanitized-pdf"

    return pipeline


# ---------------------------------------------------------------------------
# Entity filtering tests
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestEntityFiltering:
    def test_filter_single_entity(self):
        """Only PERSON_NAME should be redacted; others should have redacted=False."""
        findings = _make_findings()
        pipeline = _make_pipeline_with_mocks(findings)

        result = pipeline.process(
            file_content=b"%PDF-fake",
            filename="test.pdf",
            level=SanitizationLevel.STANDARD,
            redact_entities=["PERSON_NAME"],
        )

        # All findings should be in result
        assert len(result.findings) == 3

        redacted = [f for f in result.findings if f.redacted]
        not_redacted = [f for f in result.findings if not f.redacted]

        assert len(redacted) == 1
        assert redacted[0].entity_type == EntityType.PERSON_NAME
        assert len(not_redacted) == 2

    def test_filter_multiple_entities(self):
        """Multiple entity types can be selected."""
        findings = _make_findings()
        pipeline = _make_pipeline_with_mocks(findings)

        result = pipeline.process(
            file_content=b"%PDF-fake",
            filename="test.pdf",
            level=SanitizationLevel.STANDARD,
            redact_entities=["PERSON_NAME", "DNI_NIE"],
        )

        redacted = [f for f in result.findings if f.redacted]
        assert len(redacted) == 2
        assert {f.entity_type for f in redacted} == {EntityType.PERSON_NAME, EntityType.DNI_NIE}

    def test_no_filter_redacts_all(self):
        """When redact_entities is None, all findings should have redacted=True."""
        findings = _make_findings()
        pipeline = _make_pipeline_with_mocks(findings)

        result = pipeline.process(
            file_content=b"%PDF-fake",
            filename="test.pdf",
            level=SanitizationLevel.STANDARD,
        )

        assert all(f.redacted for f in result.findings)

    def test_filtered_findings_excluded_from_sanitizer(self):
        """Only redacted=True findings should be passed to the sanitizer."""
        findings = _make_findings()
        pipeline = _make_pipeline_with_mocks(findings)

        pipeline.process(
            file_content=b"%PDF-fake",
            filename="test.pdf",
            level=SanitizationLevel.STANDARD,
            redact_entities=["EMAIL"],
        )

        # Check what was passed to sanitizer
        from app.pipeline.sanitizers.pdf import PdfSanitizer
        mock_sanitizer = pipeline._instance_cache[PdfSanitizer]
        call_args = mock_sanitizer.sanitize.call_args
        sanitizer_findings = call_args[0][1] if len(call_args[0]) > 1 else call_args.kwargs.get("findings", call_args[0][1])

        assert len(sanitizer_findings) == 1
        assert sanitizer_findings[0].entity_type == EntityType.EMAIL

    def test_redaction_style_passed_to_sanitizer(self):
        """RedactionStyle should be forwarded to the sanitizer."""
        findings = _make_findings()
        pipeline = _make_pipeline_with_mocks(findings)

        pipeline.process(
            file_content=b"%PDF-fake",
            filename="test.pdf",
            level=SanitizationLevel.STANDARD,
            redaction_style=RedactionStyle.PLACEHOLDER,
        )

        from app.pipeline.sanitizers.pdf import PdfSanitizer
        mock_sanitizer = pipeline._instance_cache[PdfSanitizer]
        call_kwargs = mock_sanitizer.sanitize.call_args
        assert call_kwargs.kwargs.get("style") == RedactionStyle.PLACEHOLDER


# ---------------------------------------------------------------------------
# Default backward compatibility
# ---------------------------------------------------------------------------


class TestBackwardCompatibility:
    def test_process_without_new_params(self):
        """Calling process() without new params should behave as before."""
        findings = _make_findings()
        pipeline = _make_pipeline_with_mocks(findings)

        result = pipeline.process(
            file_content=b"%PDF-fake",
            filename="test.pdf",
            level=SanitizationLevel.STANDARD,
        )

        assert len(result.findings) == 3
        assert all(f.redacted for f in result.findings)
        assert result.sanitized_content is not None
