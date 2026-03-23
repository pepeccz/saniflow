"""Audit logging for sanitization operations — compliance trail without PII."""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone

from pydantic import BaseModel

logger = logging.getLogger("saniflow.audit")


class AuditEntry(BaseModel):
    """Audit log entry. Contains NO PII — only hashes, counts, and metadata."""

    timestamp: str
    request_id: str
    input_hash: str
    input_filename: str
    input_size: int
    output_hash: str | None = None
    level: str
    findings_by_type: dict[str, int]
    total_findings: int
    processing_time_ms: int
    status: str  # "success" | "error"
    error: str | None = None
    source: str  # "api" | "mcp"
    client_ip: str | None = None


def _sha256(data: bytes) -> str:
    """Compute SHA-256 hex digest of the given bytes."""
    return hashlib.sha256(data).hexdigest()


def log_sanitization(
    *,
    file_content: bytes,
    filename: str,
    level: str,
    result=None,
    processing_time_ms: int,
    source: str = "api",
    client_ip: str | None = None,
    error: str | None = None,
) -> None:
    """Log a sanitization event to the audit log.

    All arguments are keyword-only to prevent positional arg mistakes.
    The ``result`` parameter is loosely typed to avoid coupling to
    :class:`SanitizationResult`.
    """
    from app.config import settings

    if not settings.AUDIT_ENABLED:
        return

    try:
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            request_id=str(uuid.uuid4()),
            input_hash=_sha256(file_content),
            input_filename=filename,
            input_size=len(file_content),
            output_hash=(
                _sha256(result.sanitized_content)
                if result and result.sanitized_content
                else None
            ),
            level=level,
            findings_by_type=(
                dict(result.summary.by_type) if result and result.summary else {}
            ),
            total_findings=(
                result.summary.total_findings if result and result.summary else 0
            ),
            processing_time_ms=processing_time_ms,
            status="success" if error is None else "error",
            error=error,
            source=source,
            client_ip=client_ip,
        )
        logger.info(entry.model_dump_json())
    except Exception:
        logging.getLogger(__name__).debug("Audit logging failed", exc_info=True)
