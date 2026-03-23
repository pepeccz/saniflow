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
                files={"file": ("test.xyz", b"hello world", "application/octet-stream")},
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


class TestApiKeyAuth:
    """API key authentication tests."""

    async def test_no_auth_required_when_api_keys_empty(
        self, test_client, sample_pdf_bytes: bytes
    ):
        """When SANIFLOW_API_KEYS is not set (empty), auth is disabled."""
        with patch("app.api.auth.settings") as mock_settings:
            mock_settings.API_KEYS = []

            with patch("app.api.routes.SanitizationPipeline") as mock_cls:
                mock_pipeline = MagicMock()
                mock_pipeline.process.return_value = _fake_result()
                mock_cls.return_value = mock_pipeline

                async with test_client as client:
                    resp = await client.post(
                        "/api/v1/sanitize",
                        files={"file": ("test.pdf", sample_pdf_bytes, "application/pdf")},
                        data={"level": "standard", "response_format": "file"},
                    )

        assert resp.status_code == 200

    async def test_401_when_auth_enabled_and_key_missing(
        self, test_client, sample_pdf_bytes: bytes
    ):
        """When API keys are configured but no header is sent, return 401."""
        with patch("app.api.auth.settings") as mock_settings:
            mock_settings.API_KEYS = ["secret-key-1", "secret-key-2"]

            async with test_client as client:
                resp = await client.post(
                    "/api/v1/sanitize",
                    files={"file": ("test.pdf", sample_pdf_bytes, "application/pdf")},
                    data={"level": "standard", "response_format": "file"},
                )

        assert resp.status_code == 401
        assert "Missing API key" in resp.json()["detail"]

    async def test_401_when_auth_enabled_and_key_invalid(
        self, test_client, sample_pdf_bytes: bytes
    ):
        """When API keys are configured and a wrong key is sent, return 401."""
        with patch("app.api.auth.settings") as mock_settings:
            mock_settings.API_KEYS = ["secret-key-1", "secret-key-2"]

            async with test_client as client:
                resp = await client.post(
                    "/api/v1/sanitize",
                    files={"file": ("test.pdf", sample_pdf_bytes, "application/pdf")},
                    data={"level": "standard", "response_format": "file"},
                    headers={"X-API-Key": "wrong-key"},
                )

        assert resp.status_code == 401
        assert "Invalid API key" in resp.json()["detail"]

    @patch("app.api.routes.SanitizationPipeline")
    async def test_200_when_auth_enabled_and_key_valid(
        self, mock_pipeline_cls, test_client, sample_pdf_bytes: bytes
    ):
        """When a valid API key is provided, the request succeeds."""
        mock_pipeline = MagicMock()
        mock_pipeline.process.return_value = _fake_result()
        mock_pipeline_cls.return_value = mock_pipeline

        with patch("app.api.auth.settings") as mock_settings:
            mock_settings.API_KEYS = ["secret-key-1", "secret-key-2"]

            async with test_client as client:
                resp = await client.post(
                    "/api/v1/sanitize",
                    files={"file": ("test.pdf", sample_pdf_bytes, "application/pdf")},
                    data={"level": "standard", "response_format": "file"},
                    headers={"X-API-Key": "secret-key-2"},
                )

        assert resp.status_code == 200

    async def test_health_does_not_require_auth(self, test_client):
        """Health endpoint should never require authentication."""
        with patch("app.api.auth.settings") as mock_settings:
            mock_settings.API_KEYS = ["secret-key-1"]

            async with test_client as client:
                resp = await client.get("/api/v1/health")

        assert resp.status_code == 200


class TestRateLimiting:
    """Rate limiting tests for POST /api/v1/sanitize."""

    @patch("app.api.routes.SanitizationPipeline")
    async def test_under_limit_passes(
        self, mock_pipeline_cls, test_client, sample_pdf_bytes: bytes
    ):
        """Requests under the rate limit succeed with rate limit headers."""
        from app.api.rate_limit import reset_store

        reset_store()

        mock_pipeline = MagicMock()
        mock_pipeline.process.return_value = _fake_result()
        mock_pipeline_cls.return_value = mock_pipeline

        with patch("app.api.rate_limit.settings") as mock_rl_settings:
            mock_rl_settings.RATE_LIMIT = 5

            async with test_client as client:
                resp = await client.post(
                    "/api/v1/sanitize",
                    files={"file": ("test.pdf", sample_pdf_bytes, "application/pdf")},
                    data={"level": "standard", "response_format": "file"},
                )

        assert resp.status_code == 200
        assert "x-ratelimit-limit" in resp.headers
        assert resp.headers["x-ratelimit-limit"] == "5"
        assert "x-ratelimit-remaining" in resp.headers
        assert "x-ratelimit-reset" in resp.headers

    @patch("app.api.routes.SanitizationPipeline")
    async def test_over_limit_returns_429(
        self, mock_pipeline_cls, test_client, sample_pdf_bytes: bytes
    ):
        """Exceeding the rate limit returns 429 with Retry-After header."""
        from app.api.rate_limit import reset_store

        reset_store()

        mock_pipeline = MagicMock()
        mock_pipeline.process.return_value = _fake_result()
        mock_pipeline_cls.return_value = mock_pipeline

        with patch("app.api.rate_limit.settings") as mock_rl_settings:
            mock_rl_settings.RATE_LIMIT = 2

            async with test_client as client:
                # First two requests should succeed
                for _ in range(2):
                    resp = await client.post(
                        "/api/v1/sanitize",
                        files={"file": ("test.pdf", sample_pdf_bytes, "application/pdf")},
                        data={"level": "standard", "response_format": "file"},
                    )
                    assert resp.status_code == 200

                # Third request should be rate limited
                resp = await client.post(
                    "/api/v1/sanitize",
                    files={"file": ("test.pdf", sample_pdf_bytes, "application/pdf")},
                    data={"level": "standard", "response_format": "file"},
                )

        assert resp.status_code == 429
        assert "retry-after" in resp.headers
        body = resp.json()
        assert body["detail"] == "Too many requests"

    @patch("app.api.routes.SanitizationPipeline")
    async def test_different_ips_tracked_separately(
        self, mock_pipeline_cls, sample_pdf_bytes: bytes
    ):
        """Each client IP gets its own rate limit counter."""
        from httpx import ASGITransport, AsyncClient

        from app.api.rate_limit import reset_store
        from app.main import app

        reset_store()

        mock_pipeline = MagicMock()
        mock_pipeline.process.return_value = _fake_result()
        mock_pipeline_cls.return_value = mock_pipeline

        with patch("app.api.rate_limit.settings") as mock_rl_settings:
            mock_rl_settings.RATE_LIMIT = 1

            # First client uses up its limit
            transport1 = ASGITransport(app=app, client=("10.0.0.1", 1234))
            async with AsyncClient(transport=transport1, base_url="http://test") as client1:
                resp = await client1.post(
                    "/api/v1/sanitize",
                    files={"file": ("test.pdf", sample_pdf_bytes, "application/pdf")},
                    data={"level": "standard", "response_format": "file"},
                )
                assert resp.status_code == 200

                # Same client is now rate limited
                resp = await client1.post(
                    "/api/v1/sanitize",
                    files={"file": ("test.pdf", sample_pdf_bytes, "application/pdf")},
                    data={"level": "standard", "response_format": "file"},
                )
                assert resp.status_code == 429

            # Different client still has its own quota
            transport2 = ASGITransport(app=app, client=("10.0.0.2", 1234))
            async with AsyncClient(transport=transport2, base_url="http://test") as client2:
                resp = await client2.post(
                    "/api/v1/sanitize",
                    files={"file": ("test.pdf", sample_pdf_bytes, "application/pdf")},
                    data={"level": "standard", "response_format": "file"},
                )
                assert resp.status_code == 200

    async def test_health_not_rate_limited(self, test_client):
        """Health endpoint is never rate limited."""
        from app.api.rate_limit import reset_store

        reset_store()

        with patch("app.api.rate_limit.settings") as mock_rl_settings:
            mock_rl_settings.RATE_LIMIT = 1

            async with test_client as client:
                # Health should always work regardless of rate limit
                for _ in range(5):
                    resp = await client.get("/api/v1/health")
                    assert resp.status_code == 200
