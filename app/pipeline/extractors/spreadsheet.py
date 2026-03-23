"""Spreadsheet extractors.

Extracts text from spreadsheet formats (CSV, XLSX, ODS) by concatenating
cell values as ``"header: value\\n"`` per cell, row by row.  Returns an
``ExtractionResult`` with an empty ``SpanMap``.
"""

from __future__ import annotations

import csv
import io

from app.models.extraction import ExtractionResult, SpanMap


def _require_odfpy() -> None:
    """Raise ``RuntimeError`` if odfpy is not installed."""
    try:
        import odf  # noqa: F401
    except ImportError:
        raise RuntimeError(
            "odfpy is required for ODS support. "
            "Install with: pip install 'saniflow[documents]'"
        )


def _require_openpyxl() -> None:
    """Raise ``RuntimeError`` if openpyxl is not installed."""
    try:
        import openpyxl  # noqa: F401
    except ImportError:
        raise RuntimeError(
            "openpyxl is required for XLSX support. "
            "Install with: pip install 'saniflow[spreadsheet]'"
        )


class CsvExtractor:
    """Extract text content from CSV files.

    Implements the ``Extractor`` protocol.

    Parses CSV via the stdlib ``csv`` module, detects headers from the
    first row, and concatenates text as ``"header: value\\n"`` per cell.
    """

    def extract(self, file_content: bytes, filename: str) -> ExtractionResult:
        """Decode *file_content* as UTF-8, parse CSV, and return an ``ExtractionResult``.

        Args:
            file_content: Raw bytes of the CSV file.
            filename: Original filename (unused beyond protocol compliance).

        Returns:
            An ``ExtractionResult`` with the flattened text, an empty SpanMap,
            no images, ``pages=1``, and ``is_scanned=False``.
        """
        text_content = file_content.decode("utf-8", errors="replace")
        reader = csv.reader(io.StringIO(text_content))

        rows = list(reader)
        if not rows:
            return ExtractionResult(
                text="",
                span_map=SpanMap(),
                images=[],
                pages=1,
                is_scanned=False,
            )

        headers = rows[0]
        parts: list[str] = []

        if len(rows) == 1:
            # Single row (headers only, no data) — treat as values with
            # numeric column headers.
            for col_idx, value in enumerate(headers):
                if value:
                    parts.append(f"{col_idx}: {value}\n")
        else:
            for row in rows[1:]:
                for col_idx, value in enumerate(row):
                    if col_idx < len(headers) and headers[col_idx]:
                        header = headers[col_idx]
                    else:
                        header = str(col_idx)
                    if value:
                        parts.append(f"{header}: {value}\n")

        return ExtractionResult(
            text="".join(parts),
            span_map=SpanMap(),
            images=[],
            pages=1,
            is_scanned=False,
        )


class XlsxExtractor:
    """Extract text content from XLSX files.

    Implements the ``Extractor`` protocol.

    Loads the workbook via ``openpyxl``, iterates all sheets and rows,
    uses the first row of each sheet as headers, and concatenates text
    as ``"header: value\\n"`` per cell.  Multi-sheet workbooks are
    prefixed with ``"--- Sheet: {name} ---\\n"`` per sheet.
    """

    def extract(self, file_content: bytes, filename: str) -> ExtractionResult:
        """Parse *file_content* as XLSX and return an ``ExtractionResult``.

        Args:
            file_content: Raw bytes of the XLSX file.
            filename: Original filename (unused beyond protocol compliance).

        Returns:
            An ``ExtractionResult`` with the flattened text, an empty SpanMap,
            no images, ``pages`` equal to the number of sheets, and
            ``is_scanned=False``.
        """
        _require_openpyxl()
        import openpyxl

        wb = openpyxl.load_workbook(io.BytesIO(file_content), data_only=True)
        parts: list[str] = []

        for sheet in wb.worksheets:
            parts.append(f"--- Sheet: {sheet.title} ---\n")

            rows = list(sheet.iter_rows(values_only=True))
            if not rows:
                continue

            headers = [
                str(cell) if cell is not None else str(idx)
                for idx, cell in enumerate(rows[0])
            ]

            for row in rows[1:]:
                for col_idx, cell in enumerate(row):
                    if cell is None:
                        continue
                    value = str(cell)
                    if not value:
                        continue
                    header = headers[col_idx] if col_idx < len(headers) else str(col_idx)
                    parts.append(f"{header}: {value}\n")

        return ExtractionResult(
            text="".join(parts),
            span_map=SpanMap(),
            images=[],
            pages=len(wb.worksheets),
            is_scanned=False,
        )


class OdsExtractor:
    """Extract text content from ODS files.

    Implements the ``Extractor`` protocol.

    Loads the spreadsheet via ``odfpy``, iterates all sheets and rows,
    uses the first row of each sheet as headers, and concatenates text
    as ``"header: value\\n"`` per cell.  Multi-sheet workbooks are
    prefixed with ``"--- Sheet: {name} ---\\n"`` per sheet.
    """

    def extract(self, file_content: bytes, filename: str) -> ExtractionResult:
        """Parse *file_content* as ODS and return an ``ExtractionResult``.

        Args:
            file_content: Raw bytes of the ODS file.
            filename: Original filename (unused beyond protocol compliance).

        Returns:
            An ``ExtractionResult`` with the flattened text, an empty SpanMap,
            no images, ``pages`` equal to the number of sheets, and
            ``is_scanned=False``.
        """
        _require_odfpy()
        from odf.opendocument import load
        from odf.table import Table, TableCell, TableRow
        from odf.text import P

        doc = load(io.BytesIO(file_content))
        sheets = doc.spreadsheet.getElementsByType(Table)
        parts: list[str] = []

        for sheet in sheets:
            sheet_name = sheet.getAttribute("name")
            parts.append(f"--- Sheet: {sheet_name} ---\n")

            rows_data: list[list[str]] = []
            for row in sheet.getElementsByType(TableRow):
                cells: list[str] = []
                for cell in row.getElementsByType(TableCell):
                    repeat = cell.getAttribute("numbercolumnsrepeated")
                    repeat_count = int(repeat) if repeat else 1
                    text_content = ""
                    for p in cell.getElementsByType(P):
                        text_content += "".join(
                            t.data for t in p.childNodes if hasattr(t, "data")
                        )
                    cells.extend([text_content] * repeat_count)
                rows_data.append(cells)

            if not rows_data:
                continue

            headers = rows_data[0]

            for row in rows_data[1:]:
                for col_idx, value in enumerate(row):
                    if not value:
                        continue
                    if col_idx < len(headers) and headers[col_idx]:
                        header = headers[col_idx]
                    else:
                        header = str(col_idx)
                    parts.append(f"{header}: {value}\n")

        return ExtractionResult(
            text="".join(parts),
            span_map=SpanMap(),
            images=[],
            pages=len(sheets),
            is_scanned=False,
        )
