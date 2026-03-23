"""Tests for ODS extractor and sanitizer (tasks 4.2 and 4.3)."""

from __future__ import annotations

import io

import pytest

from app.models.extraction import ExtractionResult, SpanMap
from app.models.findings import EntityType, Finding, RedactionStyle
from app.pipeline.extractors.spreadsheet import OdsExtractor
from app.pipeline.sanitizers.spreadsheet import OdsSanitizer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ods(sheets: dict[str, list[list[str]]]) -> bytes:
    """Build an ODS file in memory from a dict of sheet_name -> rows."""
    from odf.opendocument import OpenDocumentSpreadsheet
    from odf.table import Table, TableCell, TableRow
    from odf.text import P

    doc = OpenDocumentSpreadsheet()

    for name, rows in sheets.items():
        table = Table(name=name)
        for row_data in rows:
            tr = TableRow()
            for value in row_data:
                tc = TableCell()
                if value:
                    p = P()
                    p.addText(str(value))
                    tc.addElement(p)
                tr.addElement(tc)
            table.addElement(tr)
        doc.spreadsheet.addElement(table)

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# OdsExtractor tests
# ---------------------------------------------------------------------------


class TestOdsExtractor:
    """Verify ODS extraction produces header: value text."""

    def test_single_sheet_extraction(self):
        content = _make_ods({
            "People": [
                ["Name", "Email"],
                ["Juan Garcia", "juan@test.com"],
            ],
        })
        extractor = OdsExtractor()
        result = extractor.extract(content, "test.ods")

        assert isinstance(result, ExtractionResult)
        assert "--- Sheet: People ---\n" in result.text
        assert "Name: Juan Garcia\n" in result.text
        assert "Email: juan@test.com\n" in result.text
        assert len(result.span_map) == 0
        assert result.pages == 1
        assert result.is_scanned is False

    def test_multi_sheet_extraction(self):
        content = _make_ods({
            "Employees": [
                ["Name", "DNI"],
                ["Juan Garcia", "12345678Z"],
            ],
            "Clients": [
                ["Name", "Phone"],
                ["Maria Lopez", "+34 612345678"],
            ],
        })
        extractor = OdsExtractor()
        result = extractor.extract(content, "multi.ods")

        assert "--- Sheet: Employees ---\n" in result.text
        assert "Name: Juan Garcia\n" in result.text
        assert "DNI: 12345678Z\n" in result.text
        assert "--- Sheet: Clients ---\n" in result.text
        assert "Name: Maria Lopez\n" in result.text
        assert "Phone: +34 612345678\n" in result.text
        assert result.pages == 2

    def test_empty_spreadsheet(self):
        content = _make_ods({"Empty": []})
        extractor = OdsExtractor()
        result = extractor.extract(content, "empty.ods")

        assert "--- Sheet: Empty ---\n" in result.text
        assert result.text.strip() == "--- Sheet: Empty ---"
        assert result.pages == 1
        assert result.is_scanned is False

    def test_images_list_is_empty(self):
        content = _make_ods({"A": [["X"], ["1"]]})
        extractor = OdsExtractor()
        result = extractor.extract(content, "test.ods")

        assert result.images == []

    def test_headers_only_sheet(self):
        """Sheet with only one row (headers, no data) produces no value lines."""
        content = _make_ods({"Headers": [["Name", "Email"]]})
        extractor = OdsExtractor()
        result = extractor.extract(content, "headers_only.ods")

        assert "--- Sheet: Headers ---\n" in result.text
        assert "Name:" not in result.text


# ---------------------------------------------------------------------------
# OdsSanitizer tests
# ---------------------------------------------------------------------------


class TestOdsSanitizer:
    """Verify ODS sanitization replaces PII and preserves structure."""

    def test_basic_redaction_black_style(self):
        content = _make_ods({
            "People": [
                ["Name", "Email"],
                ["Juan Garcia", "juan@test.com"],
            ],
        })
        findings = [
            Finding(entity_type=EntityType.PERSON_NAME, original_text="Juan Garcia", score=0.9),
            Finding(entity_type=EntityType.EMAIL, original_text="juan@test.com", score=0.99),
        ]
        sanitizer = OdsSanitizer()
        result_bytes = sanitizer.sanitize(content, findings, "test.ods", style=RedactionStyle.BLACK)

        # Re-extract to verify redaction.
        extractor = OdsExtractor()
        result = extractor.extract(result_bytes, "test.ods")

        assert "Juan Garcia" not in result.text
        assert "juan@test.com" not in result.text
        assert "\u2588" * 11 in result.text  # len("Juan Garcia")
        assert "\u2588" * 13 in result.text  # len("juan@test.com")

    def test_placeholder_style(self):
        content = _make_ods({
            "Sheet1": [
                ["Name", "Email"],
                ["Juan Garcia", "juan@test.com"],
            ],
        })
        findings = [
            Finding(entity_type=EntityType.EMAIL, original_text="juan@test.com", score=0.99),
        ]
        sanitizer = OdsSanitizer()
        result_bytes = sanitizer.sanitize(content, findings, "test.ods", style=RedactionStyle.PLACEHOLDER)

        extractor = OdsExtractor()
        result = extractor.extract(result_bytes, "test.ods")

        assert "juan@test.com" not in result.text
        assert "[EMAIL]" in result.text

    def test_blur_style_same_as_placeholder(self):
        content = _make_ods({
            "Sheet1": [
                ["Name", "Phone"],
                ["Juan", "+34 612345678"],
            ],
        })
        findings = [
            Finding(entity_type=EntityType.PHONE, original_text="+34 612345678", score=0.9),
        ]
        sanitizer = OdsSanitizer()
        result_bytes = sanitizer.sanitize(content, findings, "test.ods", style=RedactionStyle.BLUR)

        extractor = OdsExtractor()
        result = extractor.extract(result_bytes, "test.ods")

        assert "+34 612345678" not in result.text
        assert "[PHONE]" in result.text

    def test_structure_preserved(self):
        content = _make_ods({
            "Data": [
                ["A", "B", "C"],
                ["1", "2", "3"],
                ["4", "5", "6"],
            ],
        })
        findings = [
            Finding(entity_type=EntityType.PERSON_NAME, original_text="2", score=0.9),
        ]
        sanitizer = OdsSanitizer()
        result_bytes = sanitizer.sanitize(content, findings, "test.ods")

        extractor = OdsExtractor()
        result = extractor.extract(result_bytes, "test.ods")

        # Headers and non-PII data should still be present.
        assert "A: 1\n" in result.text
        assert "C: 3\n" in result.text
        assert "A: 4\n" in result.text
        assert "C: 6\n" in result.text

    def test_no_findings_returns_valid_ods(self):
        content = _make_ods({"Sheet1": [["A", "B"], ["1", "2"]]})
        sanitizer = OdsSanitizer()
        result_bytes = sanitizer.sanitize(content, [], "test.ods")

        extractor = OdsExtractor()
        result = extractor.extract(result_bytes, "test.ods")

        assert "A: 1\n" in result.text
        assert "B: 2\n" in result.text

    def test_finding_without_original_text_is_skipped(self):
        content = _make_ods({"Sheet1": [["A"], ["1"]]})
        findings = [
            Finding(entity_type=EntityType.FACE, original_text=None, score=0.9),
        ]
        sanitizer = OdsSanitizer()
        result_bytes = sanitizer.sanitize(content, findings, "test.ods")

        extractor = OdsExtractor()
        result = extractor.extract(result_bytes, "test.ods")

        assert "A: 1\n" in result.text


# ---------------------------------------------------------------------------
# Import guard tests
# ---------------------------------------------------------------------------


class TestOdfpyImportGuard:
    """Verify _require_odfpy raises RuntimeError when odfpy is missing."""

    def test_raises_without_odfpy(self, monkeypatch):
        import app.pipeline.extractors.spreadsheet as mod

        original_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__

        def _mock_import(name, *args, **kwargs):
            if name == "odf":
                raise ImportError("No module named 'odf'")
            return original_import(name, *args, **kwargs)

        monkeypatch.setattr("builtins.__import__", _mock_import)

        with pytest.raises(RuntimeError, match="odfpy is required"):
            mod._require_odfpy()
