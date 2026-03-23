"""Tests for the audit logging module."""

from __future__ import annotations

import hashlib
import json
import logging
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app.audit import AuditEntry, _sha256, log_sanitization


# ---------------------------------------------------------------------------
# AuditEntry model tests
# ---------------------------------------------------------------------------


class TestAuditEntry:
    """Validate that AuditEntry accepts valid data and serialises correctly."""

    def _valid_data(self, **overrides) -> dict:
        base = {
            "timestamp": "2026-03-23T12:00:00+00:00",
            "request_id": "550e8400-e29b-41d4-a716-446655440000",
            "input_hash": "abc123",
            "input_filename": "test.pdf",
            "input_size": 1024,
            "output_hash": "def456",
            "level": "standard",
            "findings_by_type": {"PERSON_NAME": 2, "DNI_NIE": 1},
            "total_findings": 3,
            "processing_time_ms": 150,
            "status": "success",
            "source": "api",
            "client_ip": "127.0.0.1",
        }
        base.update(overrides)
        return base

    def test_valid_entry(self):
        entry = AuditEntry(**self._valid_data())
        assert entry.status == "success"
        assert entry.total_findings == 3
        assert entry.source == "api"

    def test_error_entry(self):
        entry = AuditEntry(**self._valid_data(status="error", error="boom"))
        assert entry.status == "error"
        assert entry.error == "boom"

    def test_optional_fields_default_to_none(self):
        entry = AuditEntry(**self._valid_data(output_hash=None, error=None, client_ip=None))
        assert entry.output_hash is None
        assert entry.error is None
        assert entry.client_ip is None

    def test_serialisation_contains_no_original_text(self):
        """Audit entries must NEVER contain an 'original_text' field."""
        entry = AuditEntry(**self._valid_data())
        dumped = entry.model_dump_json()
        parsed = json.loads(dumped)
        assert "original_text" not in parsed

    def test_serialisation_contains_no_bbox(self):
        """Audit entries must NEVER contain a 'bbox' field."""
        entry = AuditEntry(**self._valid_data())
        dumped = entry.model_dump_json()
        parsed = json.loads(dumped)
        assert "bbox" not in parsed


# ---------------------------------------------------------------------------
# _sha256 tests
# ---------------------------------------------------------------------------


class TestSha256:
    def test_known_hash(self):
        data = b"hello world"
        expected = hashlib.sha256(data).hexdigest()
        assert _sha256(data) == expected

    def test_empty_bytes(self):
        expected = hashlib.sha256(b"").hexdigest()
        assert _sha256(b"") == expected


# ---------------------------------------------------------------------------
# log_sanitization tests
# ---------------------------------------------------------------------------


def _make_result(sanitized_content: bytes | None = b"redacted"):
    """Create a minimal result-like object."""
    summary = SimpleNamespace(
        total_findings=2,
        by_type={"PERSON_NAME": 1, "EMAIL": 1},
    )
    return SimpleNamespace(
        sanitized_content=sanitized_content,
        summary=summary,
    )


class TestLogSanitization:
    def test_writes_to_logger_when_enabled(self):
        result = _make_result()
        with patch("app.audit.logger") as mock_logger:
            log_sanitization(
                file_content=b"test content",
                filename="test.pdf",
                level="standard",
                result=result,
                processing_time_ms=42,
                source="api",
                client_ip="10.0.0.1",
            )
        mock_logger.info.assert_called_once()
        logged_json = mock_logger.info.call_args[0][0]
        parsed = json.loads(logged_json)
        assert parsed["status"] == "success"
        assert parsed["total_findings"] == 2
        assert parsed["source"] == "api"
        assert parsed["client_ip"] == "10.0.0.1"
        assert parsed["processing_time_ms"] == 42
        assert "original_text" not in parsed

    def test_skips_when_disabled(self):
        with patch("app.config.settings") as mock_settings:
            mock_settings.AUDIT_ENABLED = False
            with patch("app.audit.logger") as mock_logger:
                log_sanitization(
                    file_content=b"data",
                    filename="x.pdf",
                    level="standard",
                    processing_time_ms=10,
                    source="api",
                )
            mock_logger.info.assert_not_called()

    def test_error_status(self):
        with patch("app.audit.logger") as mock_logger:
            log_sanitization(
                file_content=b"data",
                filename="bad.pdf",
                level="strict",
                result=None,
                processing_time_ms=5,
                source="mcp",
                error="Pipeline exploded",
            )
        logged_json = mock_logger.info.call_args[0][0]
        parsed = json.loads(logged_json)
        assert parsed["status"] == "error"
        assert parsed["error"] == "Pipeline exploded"
        assert parsed["total_findings"] == 0
        assert parsed["findings_by_type"] == {}

    def test_no_output_hash_when_no_sanitized_content(self):
        result = _make_result(sanitized_content=None)
        with patch("app.audit.logger") as mock_logger:
            log_sanitization(
                file_content=b"data",
                filename="test.pdf",
                level="standard",
                result=result,
                processing_time_ms=10,
                source="api",
            )
        logged_json = mock_logger.info.call_args[0][0]
        parsed = json.loads(logged_json)
        assert parsed["output_hash"] is None

    def test_does_not_raise_on_internal_failure(self):
        """Audit failures must not propagate — they are silently swallowed."""
        with patch("app.audit.logger") as mock_logger:
            mock_logger.info.side_effect = RuntimeError("disk full")
            # Should NOT raise
            log_sanitization(
                file_content=b"data",
                filename="test.pdf",
                level="standard",
                processing_time_ms=10,
                source="api",
            )
