"""API tests for the Saniflow /api/v1 endpoints.

Uses httpx.AsyncClient with ASGITransport to test the FastAPI app.
The SanitizationPipeline is mocked to avoid needing Presidio, Tesseract,
spaCy models, etc.

NOTE: sys.modules mocking for presidio_analyzer is handled by conftest.py.
"""

from __future__ import annotations

import base64
from unittest.mock import MagicMock, patch

import pytest

from app.models.findings import (
    BBox,
    EntityType,
    Finding,
    FindingSummary,
    SanitizationLevel,
    SanitizationResult,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fake_result(
    filename: str = "test.pdf",
    include_content: bool = True,
) -> SanitizationResult:
    """Build a minimal SanitizationResult for mocking."""
    findings = [
        Finding(
            entity_type=EntityType.EMAIL,
            original_text="juan@example.com",
            score=0.99,
            page=0,
            bbox=BBox(x0=72, y0=60, x1=200, y1=74),
        ),
    ]
    summary = FindingSummary(
        total_findings=1,
        by_type={"EMAIL": 1},
        level_applied=SanitizationLevel.STANDARD,
    )
    stem, ext = filename.rsplit(".", 1)
    return SanitizationResult(
        findings=findings,
        summary=summary,
        sanitized_content=b"%PDF-fake-sanitized" if include_content else None,
        original_filename=filename,
        output_filename=f"{stem}_sanitized.{ext}",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSanitizeEndpoint:
    """POST /api/v1/sanitize tests."""

    @patch("app.api.routes.SanitizationPipeline")
    async def test_sanitize_pdf_returns_file(
        self,
        mock_pipeline_cls,
        test_client,
        sample_pdf_bytes: bytes,
    ):
        mock_pipeline = MagicMock()
        mock_pipeline.process.return_value = _fake_result()
        mock_pipeline_cls.return_value = mock_pipeline

        async with test_client as client:
            resp = await client.post(
                "/api/v1/sanitize",
                files={"file": ("test.pdf", sample_pdf_bytes, "application/pdf")},
                data={"level": "standard", "response_format": "file"},
            )

        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/pdf"
        assert "test_sanitized.pdf" in resp.headers.get("content-disposition", "")

    @patch("app.api.routes.SanitizationPipeline")
    async def test_sanitize_json_format(
        self,
        mock_pipeline_cls,
        test_client,
        sample_pdf_bytes: bytes,
    ):
        mock_pipeline = MagicMock()
        mock_pipeline.process.return_value = _fake_result(include_content=False)
        mock_pipeline_cls.return_value = mock_pipeline

        async with test_client as client:
            resp = await client.post(
                "/api/v1/sanitize",
                files={"file": ("test.pdf", sample_pdf_bytes, "application/pdf")},
                data={"level": "standard", "response_format": "json"},
            )

        assert resp.status_code == 200
        body = resp.json()
        assert "findings" in body
        assert "summary" in body
        assert body["summary"]["total_findings"] == 1

    @patch("app.api.routes.SanitizationPipeline")
    async def test_sanitize_full_format(
        self,
        mock_pipeline_cls,
        test_client,
        sample_pdf_bytes: bytes,
    ):
        mock_pipeline = MagicMock()
        mock_pipeline.process.return_value = _fake_result()
        mock_pipeline_cls.return_value = mock_pipeline

        async with test_client as client:
            resp = await client.post(
                "/api/v1/sanitize",
                files={"file": ("test.pdf", sample_pdf_bytes, "application/pdf")},
                data={"level": "standard", "response_format": "full"},
            )

        assert resp.status_code == 200
        body = resp.json()
        assert "findings" in body
        assert "summary" in body
        assert "file" in body
        decoded = base64.b64decode(body["file"])
        assert decoded == b"%PDF-fake-sanitized"

    async def test_file_too_large_returns_413(self, test_client, sample_pdf_bytes: bytes):
        """Uploading a file beyond MAX_FILE_SIZE triggers 413."""
        with patch("app.api.routes.settings") as mock_settings:
            mock_settings.MAX_FILE_SIZE = 10  # 10 bytes
            mock_settings.SUPPORTED_FORMATS = [
                "application/pdf",
                "image/jpeg",
                "image/png",
            ]

            async with test_client as client:
                resp = await client.post(
                    "/api/v1/sanitize",
                    files={"file": ("test.pdf", sample_pdf_bytes, "application/pdf")},
                )

        assert resp.status_code == 413

    async def test_unsupported_format_returns_415(self, test_client):
        """Uploading a file with unsupported content type triggers 415."""
        async with test_client as client:
            resp = await client.post(
                "/api/v1/sanitize",
                files={"file": ("test.txt", b"hello world", "text/plain")},
            )

        assert resp.status_code == 415


class TestHealthEndpoint:
    """GET /api/v1/health tests."""

    async def test_health_returns_200(self, test_client):
        async with test_client as client:
            resp = await client.get("/api/v1/health")

        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "healthy"
        assert body["version"] == "0.1.0"
