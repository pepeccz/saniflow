"""In-memory processing metrics for observability.

Tracks request counts, success/error rates, processing times, and
entity type distribution.  All counters reset on application restart.
"""

from __future__ import annotations

import threading
from collections import defaultdict


class Metrics:
    """Thread-safe, in-memory metrics collector."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.total_requests: int = 0
        self.successful: int = 0
        self.failed: int = 0
        self.total_processing_time_ms: int = 0
        self.findings_by_type: dict[str, int] = defaultdict(int)

    def record_success(self, processing_time_ms: int, findings_by_type: dict[str, int]) -> None:
        """Record a successful sanitization request."""
        with self._lock:
            self.total_requests += 1
            self.successful += 1
            self.total_processing_time_ms += processing_time_ms
            for entity_type, count in findings_by_type.items():
                self.findings_by_type[entity_type] += count

    def record_failure(self, processing_time_ms: int) -> None:
        """Record a failed sanitization request."""
        with self._lock:
            self.total_requests += 1
            self.failed += 1
            self.total_processing_time_ms += processing_time_ms

    def snapshot(self) -> dict:
        """Return a point-in-time copy of all metrics."""
        with self._lock:
            avg_time = self.total_processing_time_ms / max(self.total_requests, 1)
            return {
                "total_requests": self.total_requests,
                "successful": self.successful,
                "failed": self.failed,
                "avg_processing_time_ms": round(avg_time),
                "findings_by_type": dict(self.findings_by_type),
            }


# Module-level singleton
metrics = Metrics()
