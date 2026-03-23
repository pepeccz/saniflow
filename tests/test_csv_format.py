"""Tests for CSV extractor and sanitizer (tasks 1.1 and 1.2)."""

from __future__ import annotations

import csv
import io

import pytest

from app.models.extraction import ExtractionResult, SpanMap
from app.models.findings import EntityType, Finding, RedactionStyle
from app.pipeline.extractors.spreadsheet import CsvExtractor
from app.pipeline.sanitizers.spreadsheet import CsvSanitizer


# ---------------------------------------------------------------------------
# CsvExtractor tests
# ---------------------------------------------------------------------------


class TestCsvExtractor:
    """Verify CSV extraction produces header: value text."""

    def test_basic_csv_extraction(self):
        content = "Name,Email\nJuan Garcia,juan@test.com\n".encode("utf-8")
        extractor = CsvExtractor()
        result = extractor.extract(content, "test.csv")

        assert isinstance(result, ExtractionResult)
        assert "Name: Juan Garcia\n" in result.text
        assert "Email: juan@test.com\n" in result.text
        assert len(result.span_map) == 0
        assert result.pages == 1
        assert result.is_scanned is False

    def test_multi_row_csv(self):
        content = "Name,DNI\nJuan Garcia,12345678Z\nMaria Lopez,87654321X\n".encode("utf-8")
        extractor = CsvExtractor()
        result = extractor.extract(content, "multi.csv")

        assert "Name: Juan Garcia\n" in result.text
        assert "DNI: 12345678Z\n" in result.text
        assert "Name: Maria Lopez\n" in result.text
        assert "DNI: 87654321X\n" in result.text

    def test_empty_csv(self):
        content = b""
        extractor = CsvExtractor()
        result = extractor.extract(content, "empty.csv")

        assert result.text == ""
        assert len(result.span_map) == 0
        assert result.pages == 1
        assert result.is_scanned is False

    def test_headers_only_csv(self):
        """A CSV with only headers (no data rows) should still produce text."""
        content = "Name,Email\n".encode("utf-8")
        extractor = CsvExtractor()
        result = extractor.extract(content, "headers_only.csv")

        # Single row is treated as values with numeric column indices.
        assert "0: Name\n" in result.text
        assert "1: Email\n" in result.text

    def test_single_column_csv(self):
        content = "Notes\nThis is a note\nAnother note\n".encode("utf-8")
        extractor = CsvExtractor()
        result = extractor.extract(content, "single_col.csv")

        assert "Notes: This is a note\n" in result.text
        assert "Notes: Another note\n" in result.text

    def test_empty_cells_are_skipped(self):
        content = "Name,Email\nJuan Garcia,\n".encode("utf-8")
        extractor = CsvExtractor()
        result = extractor.extract(content, "sparse.csv")

        assert "Name: Juan Garcia\n" in result.text
        # Empty cell should not produce an entry.
        assert "Email: \n" not in result.text

    def test_utf8_with_replacement(self):
        """Invalid UTF-8 bytes should be replaced, not crash."""
        content = b"Name\n\xff\xfe"
        extractor = CsvExtractor()
        result = extractor.extract(content, "broken.csv")

        # Should not raise; replacement chars should be present.
        assert result.text != ""
        assert result.pages == 1

    def test_images_list_is_empty(self):
        content = "A\n1\n".encode("utf-8")
        extractor = CsvExtractor()
        result = extractor.extract(content, "test.csv")

        assert result.images == []

    def test_row_with_more_columns_than_headers(self):
        """Extra columns beyond header count use numeric index."""
        content = "A,B\n1,2,3\n".encode("utf-8")
        extractor = CsvExtractor()
        result = extractor.extract(content, "extra.csv")

        assert "A: 1\n" in result.text
        assert "B: 2\n" in result.text
        assert "2: 3\n" in result.text


# ---------------------------------------------------------------------------
# CsvSanitizer tests
# ---------------------------------------------------------------------------


class TestCsvSanitizer:
    """Verify CSV sanitization replaces PII and preserves structure."""

    def test_replace_pii_black_style(self):
        content = "Name,Email\nJuan Garcia,juan@test.com\n".encode("utf-8")
        findings = [
            Finding(entity_type=EntityType.PERSON_NAME, original_text="Juan Garcia", score=0.9),
            Finding(entity_type=EntityType.EMAIL, original_text="juan@test.com", score=0.99),
        ]
        sanitizer = CsvSanitizer()
        result = sanitizer.sanitize(content, findings, "test.csv", style=RedactionStyle.BLACK)

        text = result.decode("utf-8")
        assert "Juan Garcia" not in text
        assert "juan@test.com" not in text
        assert "\u2588" * 11 in text  # len("Juan Garcia")
        assert "\u2588" * 13 in text  # len("juan@test.com")

    def test_replace_pii_placeholder_style(self):
        content = "Name,Email\nJuan Garcia,juan@test.com\n".encode("utf-8")
        findings = [
            Finding(entity_type=EntityType.EMAIL, original_text="juan@test.com", score=0.99),
        ]
        sanitizer = CsvSanitizer()
        result = sanitizer.sanitize(content, findings, "test.csv", style=RedactionStyle.PLACEHOLDER)

        text = result.decode("utf-8")
        assert "juan@test.com" not in text
        assert "[EMAIL]" in text

    def test_blur_style_same_as_placeholder(self):
        content = "Name,Phone\nJuan,+34 612345678\n".encode("utf-8")
        findings = [
            Finding(entity_type=EntityType.PHONE, original_text="+34 612345678", score=0.9),
        ]
        sanitizer = CsvSanitizer()
        result = sanitizer.sanitize(content, findings, "test.csv", style=RedactionStyle.BLUR)

        text = result.decode("utf-8")
        assert "+34 612345678" not in text
        assert "[PHONE]" in text

    def test_preserves_csv_structure(self):
        content = "A,B,C\n1,2,3\n4,5,6\n".encode("utf-8")
        findings = [
            Finding(entity_type=EntityType.PERSON_NAME, original_text="2", score=0.9),
        ]
        sanitizer = CsvSanitizer()
        result = sanitizer.sanitize(content, findings, "test.csv")

        reader = csv.reader(io.StringIO(result.decode("utf-8")))
        rows = list(reader)
        # Header + 2 data rows (csv writer may add a trailing empty row).
        data_rows = [r for r in rows if r]
        assert len(data_rows) == 3
        assert len(data_rows[0]) == 3  # 3 columns preserved
        assert len(data_rows[1]) == 3
        assert len(data_rows[2]) == 3

    def test_non_pii_cells_unchanged(self):
        content = "Name,City\nJuan Garcia,Madrid\n".encode("utf-8")
        findings = [
            Finding(entity_type=EntityType.PERSON_NAME, original_text="Juan Garcia", score=0.9),
        ]
        sanitizer = CsvSanitizer()
        result = sanitizer.sanitize(content, findings, "test.csv")

        text = result.decode("utf-8")
        assert "Madrid" in text
        assert "Juan Garcia" not in text

    def test_no_findings_returns_valid_csv(self):
        content = "A,B\n1,2\n".encode("utf-8")
        sanitizer = CsvSanitizer()
        result = sanitizer.sanitize(content, [], "test.csv")

        reader = csv.reader(io.StringIO(result.decode("utf-8")))
        rows = [r for r in list(reader) if r]
        assert len(rows) == 2
        assert rows[0] == ["A", "B"]
        assert rows[1] == ["1", "2"]

    def test_finding_without_original_text_is_skipped(self):
        content = "A\n1\n".encode("utf-8")
        findings = [
            Finding(entity_type=EntityType.FACE, original_text=None, score=0.9),
        ]
        sanitizer = CsvSanitizer()
        result = sanitizer.sanitize(content, findings, "test.csv")

        reader = csv.reader(io.StringIO(result.decode("utf-8")))
        rows = [r for r in list(reader) if r]
        assert rows[1] == ["1"]

    def test_pii_spanning_partial_cell(self):
        """PII that is part of a cell value should only replace the PII portion."""
        content = "Info\nContact: juan@test.com today\n".encode("utf-8")
        findings = [
            Finding(entity_type=EntityType.EMAIL, original_text="juan@test.com", score=0.99),
        ]
        sanitizer = CsvSanitizer()
        result = sanitizer.sanitize(content, findings, "test.csv", style=RedactionStyle.PLACEHOLDER)

        text = result.decode("utf-8")
        assert "juan@test.com" not in text
        assert "Contact: [EMAIL] today" in text
