"""Spreadsheet sanitizers.

Replaces PII in spreadsheet formats (CSV, XLSX, ODS) by re-parsing the
original bytes, locating ``Finding.original_text`` within cell values,
and replacing with the appropriate redaction string.
"""

from __future__ import annotations

import csv
import io
import logging

from app.models.findings import Finding, RedactionStyle
from app.pipeline.extractors.spreadsheet import _require_odfpy, _require_openpyxl

logger = logging.getLogger(__name__)


class CsvSanitizer:
    """Redact PII in CSV files.

    Implements the ``Sanitizer`` protocol.

    Re-parses the original CSV bytes, iterates through all cells, and
    replaces occurrences of each finding's ``original_text`` with the
    redaction replacement.  Re-serializes as CSV bytes (UTF-8).
    """

    def sanitize(
        self,
        file_content: bytes,
        findings: list[Finding],
        filename: str,
        *,
        style: RedactionStyle = RedactionStyle.BLACK,
    ) -> bytes:
        """Replace PII text in CSV cells and return sanitized bytes.

        Args:
            file_content: Original CSV file bytes (UTF-8).
            findings: PII detections with ``original_text`` populated.
            filename: Original filename (for logging).
            style: Redaction style -- ``BLACK`` uses block characters,
                ``PLACEHOLDER`` / ``BLUR`` use ``[ENTITY_TYPE]`` labels.

        Returns:
            Sanitized CSV file bytes (UTF-8).
        """
        text_content = file_content.decode("utf-8", errors="replace")
        reader = csv.reader(io.StringIO(text_content))
        rows = list(reader)

        redaction_count = 0
        for finding in findings:
            if not finding.original_text:
                continue

            replacement = self._get_replacement(finding, style)

            for row_idx, row in enumerate(rows):
                for col_idx, cell in enumerate(row):
                    if finding.original_text in cell:
                        rows[row_idx][col_idx] = cell.replace(
                            finding.original_text, replacement,
                        )
                        redaction_count += 1

        logger.info(
            "%s: redacted %d cell(s) across %d finding(s)",
            filename,
            redaction_count,
            len(findings),
        )

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerows(rows)
        return output.getvalue().encode("utf-8")

    # -- Helpers ------------------------------------------------------------

    @staticmethod
    def _get_replacement(finding: Finding, style: RedactionStyle) -> str:
        """Build the replacement string for a given finding and style."""
        if style in (RedactionStyle.PLACEHOLDER, RedactionStyle.BLUR):
            return f"[{finding.entity_type.value}]"
        # BLACK (default): unicode block characters matching original length.
        return "\u2588" * len(finding.original_text)


class XlsxSanitizer:
    """Redact PII in XLSX files.

    Implements the ``Sanitizer`` protocol.

    Loads the workbook via ``openpyxl`` (NOT ``data_only`` — we need to
    modify cells), iterates all cells in all sheets, and replaces
    occurrences of each finding's ``original_text`` with the redaction
    replacement.  Formula cells are cleared and replaced with the
    redacted string value.  Saves the workbook back to bytes.
    """

    def sanitize(
        self,
        file_content: bytes,
        findings: list[Finding],
        filename: str,
        *,
        style: RedactionStyle = RedactionStyle.BLACK,
    ) -> bytes:
        """Replace PII text in XLSX cells and return sanitized bytes.

        Args:
            file_content: Original XLSX file bytes.
            findings: PII detections with ``original_text`` populated.
            filename: Original filename (for logging).
            style: Redaction style -- ``BLACK`` uses block characters,
                ``PLACEHOLDER`` / ``BLUR`` use ``[ENTITY_TYPE]`` labels.

        Returns:
            Sanitized XLSX file bytes.
        """
        _require_openpyxl()
        import openpyxl

        wb = openpyxl.load_workbook(io.BytesIO(file_content))

        redaction_count = 0
        for finding in findings:
            if not finding.original_text:
                continue

            replacement = self._get_replacement(finding, style)

            for sheet in wb.worksheets:
                for row in sheet.iter_rows():
                    for cell in row:
                        if cell.value is None:
                            continue

                        # Formula cells: clear formula, set string value.
                        if cell.data_type == "f":
                            cell.value = replacement
                            redaction_count += 1
                            continue

                        if not isinstance(cell.value, str):
                            continue

                        if finding.original_text in cell.value:
                            cell.value = cell.value.replace(
                                finding.original_text, replacement,
                            )
                            redaction_count += 1

        logger.info(
            "%s: redacted %d cell(s) across %d finding(s)",
            filename,
            redaction_count,
            len(findings),
        )

        output = io.BytesIO()
        wb.save(output)
        return output.getvalue()

    # -- Helpers ------------------------------------------------------------

    @staticmethod
    def _get_replacement(finding: Finding, style: RedactionStyle) -> str:
        """Build the replacement string for a given finding and style."""
        if style in (RedactionStyle.PLACEHOLDER, RedactionStyle.BLUR):
            return f"[{finding.entity_type.value}]"
        # BLACK (default): unicode block characters matching original length.
        return "\u2588" * len(finding.original_text)


class OdsSanitizer:
    """Redact PII in ODS files.

    Implements the ``Sanitizer`` protocol.

    Loads the spreadsheet via ``odfpy``, iterates all cells in all sheets,
    and replaces occurrences of each finding's ``original_text`` with the
    redaction replacement.  Saves the document back to bytes.
    """

    def sanitize(
        self,
        file_content: bytes,
        findings: list[Finding],
        filename: str,
        *,
        style: RedactionStyle = RedactionStyle.BLACK,
    ) -> bytes:
        """Replace PII text in ODS cells and return sanitized bytes.

        Args:
            file_content: Original ODS file bytes.
            findings: PII detections with ``original_text`` populated.
            filename: Original filename (for logging).
            style: Redaction style -- ``BLACK`` uses block characters,
                ``PLACEHOLDER`` / ``BLUR`` use ``[ENTITY_TYPE]`` labels.

        Returns:
            Sanitized ODS file bytes.
        """
        _require_odfpy()
        from odf.opendocument import load
        from odf.table import Table, TableCell, TableRow
        from odf.text import P

        doc = load(io.BytesIO(file_content))
        sheets = doc.spreadsheet.getElementsByType(Table)

        redaction_count = 0
        for finding in findings:
            if not finding.original_text:
                continue

            replacement = self._get_replacement(finding, style)

            for sheet in sheets:
                for row in sheet.getElementsByType(TableRow):
                    for cell in row.getElementsByType(TableCell):
                        text_content = ""
                        for p in cell.getElementsByType(P):
                            text_content += "".join(
                                t.data
                                for t in p.childNodes
                                if hasattr(t, "data")
                            )

                        if finding.original_text in text_content:
                            new_text = text_content.replace(
                                finding.original_text, replacement,
                            )
                            # Remove existing P elements.
                            for p in cell.getElementsByType(P):
                                cell.removeChild(p)
                            # Add new P with replacement text.
                            new_p = P()
                            new_p.addText(new_text)
                            cell.addElement(new_p)
                            redaction_count += 1

        logger.info(
            "%s: redacted %d cell(s) across %d finding(s)",
            filename,
            redaction_count,
            len(findings),
        )

        output = io.BytesIO()
        doc.save(output)
        return output.getvalue()

    # -- Helpers ------------------------------------------------------------

    @staticmethod
    def _get_replacement(finding: Finding, style: RedactionStyle) -> str:
        """Build the replacement string for a given finding and style."""
        if style in (RedactionStyle.PLACEHOLDER, RedactionStyle.BLUR):
            return f"[{finding.entity_type.value}]"
        # BLACK (default): unicode block characters matching original length.
        return "\u2588" * len(finding.original_text)
