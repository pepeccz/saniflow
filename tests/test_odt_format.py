"""Tests for ODT format support: OdtExtractor and OdtSanitizer.

Creates fixture documents in-memory using odfpy, then verifies
extraction and sanitization behaviour including table cell handling.
"""

from __future__ import annotations

from io import BytesIO

import pytest
from odf.opendocument import OpenDocumentText
from odf.table import Table, TableCell, TableRow
from odf.text import P

from app.models.extraction import ExtractionResult
from app.models.findings import EntityType, Finding, RedactionStyle
from app.pipeline.extractors.document import OdtExtractor
from app.pipeline.sanitizers.document import OdtSanitizer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_odt(*paragraphs: str) -> bytes:
    """Create minimal ODT bytes with the given paragraph texts."""
    doc = OpenDocumentText()
    for text in paragraphs:
        p = P()
        p.addText(text)
        doc.text.addElement(p)
    buf = BytesIO()
    doc.save(buf)
    return buf.getvalue()


def _make_odt_with_table(paragraphs: list[str], table_data: list[list[str]]) -> bytes:
    """Create ODT bytes with paragraphs and a table."""
    doc = OpenDocumentText()
    for text in paragraphs:
        p = P()
        p.addText(text)
        doc.text.addElement(p)
    if table_data:
        table = Table()
        for row_data in table_data:
            row = TableRow()
            for cell_text in row_data:
                cell = TableCell()
                p = P()
                p.addText(cell_text)
                cell.addElement(p)
                row.addElement(cell)
            table.addElement(row)
        doc.text.addElement(table)
    buf = BytesIO()
    doc.save(buf)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# OdtExtractor tests
# ---------------------------------------------------------------------------


class TestOdtExtractor:
    """Tests for OdtExtractor.extract()."""

    def test_basic_paragraphs(self):
        content = _make_odt("Hello World", "Second paragraph")
        result = OdtExtractor().extract(content, "test.odt")

        assert isinstance(result, ExtractionResult)
        assert "Hello World" in result.text
        assert "Second paragraph" in result.text
        assert result.pages == 1
        assert result.is_scanned is False
        assert len(result.span_map) == 0

    def test_with_tables(self):
        content = _make_odt_with_table(
            paragraphs=["Intro"],
            table_data=[
                ["Name", "Email"],
                ["Juan Garcia", "juan@test.com"],
            ],
        )
        result = OdtExtractor().extract(content, "test.odt")

        assert "Intro" in result.text
        assert "Juan Garcia" in result.text
        assert "juan@test.com" in result.text

    def test_empty_document(self):
        content = _make_odt()
        result = OdtExtractor().extract(content, "empty.odt")

        assert result.text == ""
        assert result.pages == 1
        assert result.is_scanned is False


# ---------------------------------------------------------------------------
# OdtSanitizer tests
# ---------------------------------------------------------------------------


class TestOdtSanitizer:
    """Tests for OdtSanitizer.sanitize()."""

    def test_basic_redaction_black_style(self):
        content = _make_odt("Contact Juan Garcia for details.")
        finding = Finding(
            entity_type=EntityType.PERSON_NAME,
            original_text="Juan Garcia",
            score=0.95,
        )

        sanitized = OdtSanitizer().sanitize(
            content, [finding], "test.odt", style=RedactionStyle.BLACK,
        )

        # Re-parse and verify PII is gone.
        result = OdtExtractor().extract(sanitized, "test.odt")
        assert "Juan Garcia" not in result.text
        assert "\u2588" * len("Juan Garcia") in result.text

    def test_placeholder_style(self):
        content = _make_odt("Email: juan@test.com")
        finding = Finding(
            entity_type=EntityType.EMAIL,
            original_text="juan@test.com",
            score=0.99,
        )

        sanitized = OdtSanitizer().sanitize(
            content, [finding], "test.odt", style=RedactionStyle.PLACEHOLDER,
        )

        result = OdtExtractor().extract(sanitized, "test.odt")
        assert "juan@test.com" not in result.text
        assert "[EMAIL]" in result.text

    def test_blur_style_uses_entity_label(self):
        content = _make_odt("Phone: 612345678")
        finding = Finding(
            entity_type=EntityType.PHONE,
            original_text="612345678",
            score=0.9,
        )

        sanitized = OdtSanitizer().sanitize(
            content, [finding], "test.odt", style=RedactionStyle.BLUR,
        )

        result = OdtExtractor().extract(sanitized, "test.odt")
        assert "612345678" not in result.text
        assert "[PHONE]" in result.text

    def test_no_findings_returns_valid_odt(self):
        content = _make_odt("Nothing to redact here.")

        sanitized = OdtSanitizer().sanitize(
            content, [], "test.odt", style=RedactionStyle.BLACK,
        )

        result = OdtExtractor().extract(sanitized, "test.odt")
        assert "Nothing to redact here." in result.text


# ---------------------------------------------------------------------------
# Import guard tests
# ---------------------------------------------------------------------------


class TestOdfpyImportGuard:
    """Verify import guard raises RuntimeError with install hint."""

    def test_extractor_import_guard(self, monkeypatch):
        import builtins

        import app.pipeline.extractors.document as extractor_mod

        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "odf":
                raise ImportError("No module named 'odf'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)

        with pytest.raises(RuntimeError, match="odfpy is required"):
            extractor_mod._require_odfpy()

    def test_sanitizer_import_guard(self, monkeypatch):
        import builtins

        import app.pipeline.sanitizers.document as sanitizer_mod

        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "odf":
                raise ImportError("No module named 'odf'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)

        with pytest.raises(RuntimeError, match="odfpy is required"):
            sanitizer_mod._require_odfpy()
