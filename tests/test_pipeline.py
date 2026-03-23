"""Integration tests for the SanitizationPipeline orchestrator.

These tests use real PDF extraction (PyMuPDF) and mock the heavy
dependencies (Presidio, Tesseract, OpenCV) so tests stay fast and
don't require external models or binaries.

NOTE: sys.modules mocking for presidio_analyzer is handled by conftest.py.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.models.extraction import ExtractionResult, SpanMap
from app.models.findings import (
    BBox,
    EntityType,
    Finding,
    ResponseFormat,
    SanitizationLevel,
)
from app.pipeline.orchestrator import SanitizationPipeline


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fake_text_findings() -> list[Finding]:
    """Return a realistic list of text-based findings."""
    return [
        Finding(
            entity_type=EntityType.PERSON_NAME,
            original_text="Juan Garcia",
            score=0.85,
            page=0,
            bbox=BBox(x0=72, y0=60, x1=160, y1=74),
        ),
        Finding(
            entity_type=EntityType.EMAIL,
            original_text="juan@example.com",
            score=0.99,
            page=0,
            bbox=BBox(x0=200, y0=60, x1=350, y1=74),
        ),
    ]


def _make_pipeline_with_mocks() -> SanitizationPipeline:
    """Build a pipeline where detectors are mocked but extractors/sanitizers are real."""
    from app.pipeline.extractors.pdf import PdfExtractor
    from app.pipeline.sanitizers.pdf import PdfSanitizer

    pipeline = object.__new__(SanitizationPipeline)
    pipeline._text_detector = MagicMock()
    pipeline._visual_detector = MagicMock()
    pipeline._instance_cache = {
        PdfExtractor: PdfExtractor(),
        PdfSanitizer: PdfSanitizer(),
    }
    return pipeline


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPipelineWithPdf:
    """Pipeline processes a real PDF and returns findings."""

    def test_pdf_returns_findings(self, sample_pdf_bytes: bytes):
        pipeline = _make_pipeline_with_mocks()
        pipeline._text_detector.detect.return_value = _fake_text_findings()
        pipeline._visual_detector.detect.return_value = []

        result = pipeline.process(
            file_content=sample_pdf_bytes,
            filename="test.pdf",
            level=SanitizationLevel.STANDARD,
        )

        assert result.findings == _fake_text_findings()
        assert result.summary.total_findings == 2
        assert result.summary.by_type["PERSON_NAME"] == 1
        assert result.summary.by_type["EMAIL"] == 1
        assert result.sanitized_content is not None
        assert result.output_filename == "test_sanitized.pdf"

    def test_strict_level_runs_visual_detector(self, sample_pdf_bytes: bytes):
        pipeline = _make_pipeline_with_mocks()
        pipeline._text_detector.detect.return_value = _fake_text_findings()

        face_finding = Finding(
            entity_type=EntityType.FACE,
            original_text=None,
            score=0.95,
            page=0,
            bbox=BBox(x0=10, y0=10, x1=60, y1=60),
        )
        pipeline._visual_detector.detect.return_value = [face_finding]

        result = pipeline.process(
            file_content=sample_pdf_bytes,
            filename="test.pdf",
            level=SanitizationLevel.STRICT,
        )

        pipeline._visual_detector.detect.assert_called_once()
        assert result.summary.total_findings == 3
        assert "FACE" in result.summary.by_type

    def test_json_format_excludes_content(self, sample_pdf_bytes: bytes):
        pipeline = _make_pipeline_with_mocks()
        pipeline._text_detector.detect.return_value = []
        pipeline._visual_detector.detect.return_value = []

        result = pipeline.process(
            file_content=sample_pdf_bytes,
            filename="test.pdf",
            level=SanitizationLevel.STANDARD,
            response_format=ResponseFormat.JSON,
        )

        assert result.sanitized_content is None


@pytest.mark.integration
class TestPipelineUnsupportedType:
    """Pipeline behaviour with unsupported file formats."""

    def test_unsupported_format_raises_value_error(self):
        """Files with unrecognised MIME types raise ValueError."""
        pipeline = _make_pipeline_with_mocks()

        with pytest.raises(ValueError, match="Unsupported file format"):
            pipeline.process(
                file_content=b"not a real file",
                filename="document.xyz",
                level=SanitizationLevel.STANDARD,
            )
