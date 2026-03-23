"""Tests for RTF format support: RtfExtractor and RtfSanitizer.

Uses simple RTF strings as fixtures — no external files needed.
Verifies extraction strips control codes, sanitization replaces PII
in plain text output, and import guards raise helpful errors.
"""

from __future__ import annotations

import builtins

import pytest

from app.models.extraction import ExtractionResult
from app.models.findings import EntityType, Finding, RedactionStyle
from app.pipeline.extractors.document import RtfExtractor
from app.pipeline.sanitizers.document import RtfSanitizer


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SIMPLE_RTF = (
    r"{\rtf1\ansi{\fonttbl\f0 Arial;}\f0\fs20 Hello Juan Garcia\par}"
)

RTF_WITH_PII = (
    r"{\rtf1\ansi{\fonttbl\f0 Arial;}\f0\fs20 "
    r"Contact Juan Garcia at juan@test.com for details.\par}"
)

RTF_MULTILINE = (
    r"{\rtf1\ansi{\fonttbl\f0 Arial;}\f0\fs20 "
    r"Line one with Juan Garcia.\par Line two with 612345678.\par}"
)


# ---------------------------------------------------------------------------
# RtfExtractor tests
# ---------------------------------------------------------------------------


class TestRtfExtractor:
    """Tests for RtfExtractor.extract()."""

    def test_basic_rtf_extraction(self):
        content = SIMPLE_RTF.encode("utf-8")
        result = RtfExtractor().extract(content, "test.rtf")

        assert isinstance(result, ExtractionResult)
        assert "Hello Juan Garcia" in result.text
        assert result.pages == 1
        assert result.is_scanned is False
        assert len(result.span_map) == 0

    def test_rtf_control_codes_stripped(self):
        content = SIMPLE_RTF.encode("utf-8")
        result = RtfExtractor().extract(content, "test.rtf")

        # RTF control codes must not appear in the output.
        assert r"\rtf1" not in result.text
        assert r"\ansi" not in result.text
        assert r"\fonttbl" not in result.text
        assert r"\par" not in result.text

    def test_multiline_rtf(self):
        content = RTF_MULTILINE.encode("utf-8")
        result = RtfExtractor().extract(content, "test.rtf")

        assert "Juan Garcia" in result.text
        assert "612345678" in result.text

    def test_empty_rtf(self):
        empty_rtf = r"{\rtf1\ansi }"
        content = empty_rtf.encode("utf-8")
        result = RtfExtractor().extract(content, "empty.rtf")

        assert result.text.strip() == ""
        assert result.pages == 1
        assert result.is_scanned is False


# ---------------------------------------------------------------------------
# RtfSanitizer tests
# ---------------------------------------------------------------------------


class TestRtfSanitizer:
    """Tests for RtfSanitizer.sanitize()."""

    def test_pii_replaced_black_style(self):
        content = RTF_WITH_PII.encode("utf-8")
        finding = Finding(
            entity_type=EntityType.PERSON_NAME,
            original_text="Juan Garcia",
            score=0.95,
        )

        sanitized = RtfSanitizer().sanitize(
            content, [finding], "test.rtf", style=RedactionStyle.BLACK,
        )

        text = sanitized.decode("utf-8")
        assert "Juan Garcia" not in text
        assert "\u2588" * len("Juan Garcia") in text

    def test_pii_replaced_placeholder_style(self):
        content = RTF_WITH_PII.encode("utf-8")
        finding = Finding(
            entity_type=EntityType.EMAIL,
            original_text="juan@test.com",
            score=0.99,
        )

        sanitized = RtfSanitizer().sanitize(
            content, [finding], "test.rtf", style=RedactionStyle.PLACEHOLDER,
        )

        text = sanitized.decode("utf-8")
        assert "juan@test.com" not in text
        assert "[EMAIL]" in text

    def test_pii_replaced_blur_style(self):
        content = RTF_WITH_PII.encode("utf-8")
        finding = Finding(
            entity_type=EntityType.PERSON_NAME,
            original_text="Juan Garcia",
            score=0.95,
        )

        sanitized = RtfSanitizer().sanitize(
            content, [finding], "test.rtf", style=RedactionStyle.BLUR,
        )

        text = sanitized.decode("utf-8")
        assert "Juan Garcia" not in text
        assert "[PERSON_NAME]" in text

    def test_output_is_plain_text_not_rtf(self):
        """RTF input must produce plain text output (documented limitation)."""
        content = SIMPLE_RTF.encode("utf-8")

        sanitized = RtfSanitizer().sanitize(
            content, [], "test.rtf", style=RedactionStyle.BLACK,
        )

        text = sanitized.decode("utf-8")
        # Should NOT contain RTF control codes.
        assert r"\rtf1" not in text
        assert r"\ansi" not in text
        assert r"\fonttbl" not in text

    def test_multiple_findings(self):
        content = RTF_WITH_PII.encode("utf-8")
        findings = [
            Finding(
                entity_type=EntityType.PERSON_NAME,
                original_text="Juan Garcia",
                score=0.95,
            ),
            Finding(
                entity_type=EntityType.EMAIL,
                original_text="juan@test.com",
                score=0.99,
            ),
        ]

        sanitized = RtfSanitizer().sanitize(
            content, findings, "test.rtf", style=RedactionStyle.PLACEHOLDER,
        )

        text = sanitized.decode("utf-8")
        assert "Juan Garcia" not in text
        assert "juan@test.com" not in text
        assert "[PERSON_NAME]" in text
        assert "[EMAIL]" in text

    def test_no_findings_returns_plain_text(self):
        content = SIMPLE_RTF.encode("utf-8")

        sanitized = RtfSanitizer().sanitize(
            content, [], "test.rtf", style=RedactionStyle.BLACK,
        )

        text = sanitized.decode("utf-8")
        assert "Hello Juan Garcia" in text


# ---------------------------------------------------------------------------
# Import guard tests
# ---------------------------------------------------------------------------


class TestRtfImportGuard:
    """Verify import guards raise RuntimeError with install hint."""

    def test_extractor_import_guard(self, monkeypatch):
        import app.pipeline.extractors.document as extractor_mod

        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "striprtf":
                raise ImportError("No module named 'striprtf'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)

        with pytest.raises(RuntimeError, match="striprtf is required"):
            extractor_mod._require_striprtf()

    def test_sanitizer_import_guard(self, monkeypatch):
        import app.pipeline.sanitizers.document as sanitizer_mod

        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "striprtf":
                raise ImportError("No module named 'striprtf'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)

        with pytest.raises(RuntimeError, match="striprtf is required"):
            sanitizer_mod._require_striprtf()
