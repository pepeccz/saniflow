"""Tests for the MCP server helpers and tool functions."""

from __future__ import annotations

import base64
from pathlib import Path
from unittest.mock import patch

import pytest

from app.models.findings import (
    EntityType,
    Finding,
    FindingSummary,
    ResponseFormat,
    SanitizationLevel,
    SanitizationResult,
)

# Import helpers and tools from the MCP server module.
from app.mcp_server import (
    _parse_format,
    _parse_level,
    _validate_file,
    check_pii,
    sanitize_base64,
    sanitize_file,
)


# ── Helpers ──────────────────────────────────────────────────────────


class TestValidateFile:
    """Tests for ``_validate_file``."""

    def test_nonexistent_file(self, tmp_path: Path):
        path = tmp_path / "nope.pdf"
        assert _validate_file(path) is not None
        assert "File not found" in _validate_file(path)

    def test_unsupported_extension(self, tmp_path: Path):
        path = tmp_path / "data.xlsx"
        path.write_text("dummy")
        err = _validate_file(path)
        assert err is not None
        assert "Unsupported" in err

    def test_directory_not_a_file(self, tmp_path: Path):
        err = _validate_file(tmp_path)
        # tmp_path is a directory, not a file — should fail at exists or is_file
        assert err is not None

    def test_valid_pdf(self, tmp_path: Path):
        path = tmp_path / "test.pdf"
        path.write_bytes(b"%PDF-1.4 dummy content")
        assert _validate_file(path) is None

    def test_valid_image(self, tmp_path: Path):
        for ext in (".jpg", ".jpeg", ".png"):
            path = tmp_path / f"img{ext}"
            path.write_bytes(b"dummy image")
            assert _validate_file(path) is None, f"Failed for extension {ext}"


class TestParseLevel:
    """Tests for ``_parse_level``."""

    def test_standard(self):
        assert _parse_level("standard") == SanitizationLevel.STANDARD

    def test_strict(self):
        assert _parse_level("strict") == SanitizationLevel.STRICT

    def test_invalid_defaults_standard(self):
        assert _parse_level("banana") == SanitizationLevel.STANDARD


class TestParseFormat:
    """Tests for ``_parse_format``."""

    def test_file(self):
        assert _parse_format("file") == ResponseFormat.FILE

    def test_json(self):
        assert _parse_format("json") == ResponseFormat.JSON

    def test_full(self):
        assert _parse_format("full") == ResponseFormat.FULL

    def test_invalid_defaults_file(self):
        assert _parse_format("nope") == ResponseFormat.FILE


# ── Mock pipeline result factory ─────────────────────────────────────


def _make_result(
    *,
    findings: list[Finding] | None = None,
    sanitized_content: bytes | None = b"sanitized",
    filename: str = "test.pdf",
) -> SanitizationResult:
    if findings is None:
        findings = [
            Finding(
                entity_type=EntityType.DNI_NIE,
                original_text="12345678Z",
                score=0.95,
                page=1,
            ),
        ]
    return SanitizationResult(
        findings=findings,
        summary=FindingSummary(
            total_findings=len(findings),
            by_type={f.entity_type.value: 1 for f in findings},
            level_applied=SanitizationLevel.STANDARD,
        ),
        sanitized_content=sanitized_content,
        original_filename=filename,
        output_filename=f"{Path(filename).stem}_sanitized{Path(filename).suffix}",
    )


# ── Tool tests ───────────────────────────────────────────────────────


class TestSanitizeFile:
    """Tests for the ``sanitize_file`` MCP tool."""

    async def test_nonexistent_file(self):
        result = await sanitize_file(file_path="/tmp/nonexistent_abc123.pdf")
        assert "error" in result
        assert "File not found" in result["error"]

    async def test_unsupported_format(self, tmp_path: Path):
        path = tmp_path / "data.txt"
        path.write_text("hello")
        result = await sanitize_file(file_path=str(path))
        assert "error" in result
        assert "Unsupported" in result["error"]

    @patch("app.mcp_server._run_pipeline")
    async def test_happy_path_file_format(self, mock_pipeline, tmp_path: Path):
        pdf_path = tmp_path / "doc.pdf"
        pdf_path.write_bytes(b"%PDF-1.4 test content")

        mock_pipeline.return_value = _make_result(filename="doc.pdf")

        result = await sanitize_file(file_path=str(pdf_path), level="standard")

        assert "error" not in result
        assert result["original_file"] == str(pdf_path)
        assert len(result["findings"]) == 1
        assert result["summary"]["total_findings"] == 1
        assert "sanitized_file" in result

        # Verify sanitized file was written
        sanitized_path = Path(result["sanitized_file"])
        assert sanitized_path.exists()

    @patch("app.mcp_server._run_pipeline")
    async def test_json_format_no_sanitized_file(self, mock_pipeline, tmp_path: Path):
        pdf_path = tmp_path / "doc.pdf"
        pdf_path.write_bytes(b"%PDF-1.4 test content")

        mock_pipeline.return_value = _make_result(
            filename="doc.pdf", sanitized_content=None
        )

        result = await sanitize_file(
            file_path=str(pdf_path), response_format="json"
        )

        assert "error" not in result
        assert "sanitized_file" not in result

    @patch("app.mcp_server._run_pipeline", side_effect=RuntimeError("boom"))
    async def test_pipeline_error(self, mock_pipeline, tmp_path: Path):
        pdf_path = tmp_path / "doc.pdf"
        pdf_path.write_bytes(b"%PDF-1.4 test content")

        result = await sanitize_file(file_path=str(pdf_path))

        assert "error" in result
        assert "Processing error" in result["error"]


class TestSanitizeBase64:
    """Tests for the ``sanitize_base64`` MCP tool."""

    async def test_invalid_base64(self):
        result = await sanitize_base64(content="!!!not-base64!!!", filename="x.pdf")
        assert result == {"error": "Invalid base64 content"}

    @patch("app.mcp_server._run_pipeline")
    async def test_happy_path(self, mock_pipeline):
        mock_pipeline.return_value = _make_result(filename="report.pdf")

        b64 = base64.b64encode(b"%PDF-1.4 content").decode()
        result = await sanitize_base64(content=b64, filename="report.pdf")

        assert "error" not in result
        assert result["original_filename"] == "report.pdf"
        assert len(result["findings"]) == 1
        assert "sanitized_content_base64" in result
        assert "output_filename" in result

    @patch("app.mcp_server._run_pipeline", side_effect=RuntimeError("kaboom"))
    async def test_pipeline_error(self, mock_pipeline):
        b64 = base64.b64encode(b"data").decode()
        result = await sanitize_base64(content=b64, filename="x.pdf")
        assert "error" in result


class TestCheckPii:
    """Tests for the ``check_pii`` MCP tool."""

    async def test_nonexistent_file(self):
        result = await check_pii(file_path="/tmp/nope_xyz789.pdf")
        assert "error" in result
        assert "File not found" in result["error"]

    @patch("app.mcp_server._run_pipeline")
    async def test_happy_path_with_pii(self, mock_pipeline, tmp_path: Path):
        pdf_path = tmp_path / "doc.pdf"
        pdf_path.write_bytes(b"%PDF-1.4 test content")

        mock_pipeline.return_value = _make_result(
            filename="doc.pdf", sanitized_content=None
        )

        result = await check_pii(file_path=str(pdf_path))

        assert "error" not in result
        assert result["has_pii"] is True
        assert len(result["findings"]) == 1

    @patch("app.mcp_server._run_pipeline")
    async def test_clean_file_no_pii(self, mock_pipeline, tmp_path: Path):
        pdf_path = tmp_path / "clean.pdf"
        pdf_path.write_bytes(b"%PDF-1.4 clean")

        mock_pipeline.return_value = _make_result(
            findings=[], filename="clean.pdf", sanitized_content=None
        )

        result = await check_pii(file_path=str(pdf_path))

        assert result["has_pii"] is False
        assert result["findings"] == []
        assert result["summary"]["total_findings"] == 0

    @patch("app.mcp_server._run_pipeline", side_effect=RuntimeError("error"))
    async def test_pipeline_error(self, mock_pipeline, tmp_path: Path):
        pdf_path = tmp_path / "doc.pdf"
        pdf_path.write_bytes(b"%PDF-1.4 test")
        result = await check_pii(file_path=str(pdf_path))
        assert "error" in result
