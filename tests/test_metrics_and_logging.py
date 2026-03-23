"""Tests for structured logging and in-memory metrics."""

from __future__ import annotations

import json
import logging

import pytest

from app.metrics import Metrics


# ---------------------------------------------------------------------------
# Metrics unit tests
# ---------------------------------------------------------------------------


class TestMetrics:
    """Verify the in-memory Metrics collector."""

    def test_initial_snapshot_is_empty(self):
        m = Metrics()
        snap = m.snapshot()
        assert snap["total_requests"] == 0
        assert snap["successful"] == 0
        assert snap["failed"] == 0
        assert snap["avg_processing_time_ms"] == 0
        assert snap["findings_by_type"] == {}

    def test_record_success(self):
        m = Metrics()
        m.record_success(150, {"EMAIL": 2, "PHONE": 1})
        snap = m.snapshot()
        assert snap["total_requests"] == 1
        assert snap["successful"] == 1
        assert snap["failed"] == 0
        assert snap["avg_processing_time_ms"] == 150
        assert snap["findings_by_type"] == {"EMAIL": 2, "PHONE": 1}

    def test_record_failure(self):
        m = Metrics()
        m.record_failure(80)
        snap = m.snapshot()
        assert snap["total_requests"] == 1
        assert snap["successful"] == 0
        assert snap["failed"] == 1
        assert snap["avg_processing_time_ms"] == 80

    def test_multiple_records_average(self):
        m = Metrics()
        m.record_success(100, {"EMAIL": 1})
        m.record_success(200, {"EMAIL": 3, "PHONE": 2})
        m.record_failure(300)
        snap = m.snapshot()
        assert snap["total_requests"] == 3
        assert snap["successful"] == 2
        assert snap["failed"] == 1
        # avg = (100 + 200 + 300) / 3 = 200
        assert snap["avg_processing_time_ms"] == 200
        assert snap["findings_by_type"] == {"EMAIL": 4, "PHONE": 2}

    def test_snapshot_returns_plain_dict(self):
        """findings_by_type must be a plain dict, not defaultdict."""
        m = Metrics()
        m.record_success(50, {"DNI_NIE": 1})
        snap = m.snapshot()
        assert type(snap["findings_by_type"]) is dict


# ---------------------------------------------------------------------------
# JsonFormatter tests
# ---------------------------------------------------------------------------


class TestJsonFormatter:
    """Verify the structured JSON log formatter."""

    def test_basic_format(self):
        from app.main import JsonFormatter

        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="hello world",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)

        assert parsed["level"] == "INFO"
        assert parsed["logger"] == "test.logger"
        assert parsed["message"] == "hello world"
        assert "timestamp" in parsed

    def test_extra_fields_included(self):
        from app.main import JsonFormatter

        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="request",
            args=(),
            exc_info=None,
        )
        record.method = "POST"
        record.path = "/api/v1/sanitize"
        record.status = 200
        record.duration_ms = 42
        record.client_ip = "127.0.0.1"

        output = formatter.format(record)
        parsed = json.loads(output)

        assert parsed["method"] == "POST"
        assert parsed["path"] == "/api/v1/sanitize"
        assert parsed["status"] == 200
        assert parsed["duration_ms"] == 42
        assert parsed["client_ip"] == "127.0.0.1"


# ---------------------------------------------------------------------------
# /api/v1/metrics endpoint test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_metrics_endpoint(test_client):
    """GET /api/v1/metrics returns current metrics without auth."""
    resp = await test_client.get("/api/v1/metrics")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_requests" in data
    assert "successful" in data
    assert "failed" in data
    assert "avg_processing_time_ms" in data
    assert "findings_by_type" in data
