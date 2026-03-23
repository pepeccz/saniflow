"""Saniflow MCP Server — expose document sanitization as MCP tools."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import time
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from app.audit import log_sanitization
from app.config import settings
from app.models.findings import (
    EntityType,
    RedactionStyle,
    ResponseFormat,
    SanitizationLevel,
)
from app.pipeline.orchestrator import SanitizationPipeline

logger = logging.getLogger(__name__)

mcp = FastMCP(
    "saniflow",
    instructions="Document sanitization — detect and redact PII before AI processing",
)

pipeline = SanitizationPipeline()

# ── Helpers ──────────────────────────────────────────────────────────

_ALLOWED_EXTENSIONS: frozenset[str] = frozenset({".pdf", ".jpg", ".jpeg", ".png"})


def _validate_file(path: Path) -> str | None:
    """Return error message if file is invalid, ``None`` if OK."""
    if not path.exists():
        return f"File not found: {path}"
    if not path.is_file():
        return f"Not a file: {path}"
    if path.suffix.lower() not in _ALLOWED_EXTENSIONS:
        return (
            f"Unsupported file format: {path.suffix}. "
            f"Supported: {', '.join(sorted(_ALLOWED_EXTENSIONS))}"
        )
    if path.stat().st_size > settings.MAX_FILE_SIZE:
        return f"File too large: {path.stat().st_size} bytes (max {settings.MAX_FILE_SIZE})"
    return None


def _parse_level(level: str) -> SanitizationLevel:
    try:
        return SanitizationLevel(level)
    except ValueError:
        return SanitizationLevel.STANDARD


def _parse_format(fmt: str) -> ResponseFormat:
    try:
        return ResponseFormat(fmt)
    except ValueError:
        return ResponseFormat.FILE


def _parse_style(style: str) -> RedactionStyle:
    try:
        return RedactionStyle(style)
    except ValueError:
        return RedactionStyle.BLACK


def _parse_redact_entities(entities: str) -> list[str] | None:
    """Parse comma-separated entity types. Returns None if empty (= redact all)."""
    if not entities or not entities.strip():
        return None
    names = [e.strip() for e in entities.split(",") if e.strip()]
    if not names:
        return None
    valid_values = {et.value for et in EntityType}
    invalid = [n for n in names if n not in valid_values]
    if invalid:
        return None  # silently ignore invalid — use all entities
    return names


def _findings_to_dicts(result) -> list[dict]:
    """Convert Finding objects to serialisable dicts."""
    return [f.model_dump(exclude_none=True) for f in result.findings]


def _run_pipeline(
    content: bytes,
    filename: str,
    level: SanitizationLevel,
    fmt: ResponseFormat,
    redaction_style: RedactionStyle = RedactionStyle.BLACK,
    redact_entities: list[str] | None = None,
):
    """Synchronous pipeline call — meant to be wrapped in ``asyncio.to_thread()``."""
    return pipeline.process(
        content, filename, level, fmt,
        redaction_style=redaction_style,
        redact_entities=redact_entities,
    )


# ── Tools ────────────────────────────────────────────────────────────


@mcp.tool()
async def sanitize_file(
    file_path: str,
    level: str = "standard",
    response_format: str = "file",
    redaction_style: str = "black",
    redact_entities: str = "",
) -> dict:
    """Sanitize a document by detecting and redacting PII.

    Args:
        file_path: Absolute path to the file (PDF, JPEG, or PNG).
        level: "standard" (text PII) or "strict" (text + visual PII like faces/signatures).
        response_format: "file" returns sanitized file path + findings, "json" returns findings only, "full" returns both.
        redaction_style: "black" (default), "blur" (images only), or "placeholder" (shows entity type label).
        redact_entities: Comma-separated entity types to redact (e.g. "PERSON_NAME,EMAIL"). Empty = all.
    """
    path = Path(file_path)
    if err := _validate_file(path):
        return {"error": err}

    san_level = _parse_level(level)
    fmt = _parse_format(response_format)
    san_style = _parse_style(redaction_style)
    parsed_entities = _parse_redact_entities(redact_entities)
    file_content = path.read_bytes()

    start_time = time.monotonic()
    try:
        result = await asyncio.to_thread(
            _run_pipeline, file_content, path.name, san_level, fmt,
            san_style, parsed_entities,
        )
        processing_time_ms = int((time.monotonic() - start_time) * 1000)
        try:
            log_sanitization(
                file_content=file_content,
                filename=path.name,
                level=san_level.value,
                result=result,
                processing_time_ms=processing_time_ms,
                source="mcp",
            )
        except Exception:
            logger.debug("Audit logging failed", exc_info=True)
    except Exception as exc:
        processing_time_ms = int((time.monotonic() - start_time) * 1000)
        try:
            log_sanitization(
                file_content=file_content,
                filename=path.name,
                level=san_level.value,
                result=None,
                processing_time_ms=processing_time_ms,
                source="mcp",
                error=str(exc),
            )
        except Exception:
            logger.debug("Audit logging failed", exc_info=True)
        logger.exception("Pipeline error processing %s", file_path)
        return {"error": f"Processing error: {exc}"}

    response: dict = {
        "status": "success",
        "file": str(path),
        "findings": _findings_to_dicts(result),
        "summary": result.summary.model_dump(),
    }

    if result.sanitized_content is not None:
        output_path = path.parent / result.output_filename
        output_path.write_bytes(result.sanitized_content)
        response["sanitized_file"] = str(output_path)

    return response


@mcp.tool()
async def sanitize_base64(
    content: str,
    filename: str,
    level: str = "standard",
    redaction_style: str = "black",
    redact_entities: str = "",
) -> dict:
    """Sanitize base64-encoded file content. Use when the file is not on the local filesystem.

    Args:
        content: Base64-encoded file content.
        filename: Original filename with extension (e.g. "report.pdf").
        level: "standard" or "strict".
        redaction_style: "black" (default), "blur" (images only), or "placeholder" (shows entity type label).
        redact_entities: Comma-separated entity types to redact (e.g. "PERSON_NAME,EMAIL"). Empty = all.
    """
    try:
        file_bytes = base64.b64decode(content)
    except Exception:
        return {"error": "Invalid base64 content"}

    san_level = _parse_level(level)
    san_style = _parse_style(redaction_style)
    parsed_entities = _parse_redact_entities(redact_entities)

    start_time = time.monotonic()
    try:
        result = await asyncio.to_thread(
            _run_pipeline, file_bytes, filename, san_level, ResponseFormat.FILE,
            san_style, parsed_entities,
        )
        processing_time_ms = int((time.monotonic() - start_time) * 1000)
        try:
            log_sanitization(
                file_content=file_bytes,
                filename=filename,
                level=san_level.value,
                result=result,
                processing_time_ms=processing_time_ms,
                source="mcp",
            )
        except Exception:
            logger.debug("Audit logging failed", exc_info=True)
    except Exception as exc:
        processing_time_ms = int((time.monotonic() - start_time) * 1000)
        try:
            log_sanitization(
                file_content=file_bytes,
                filename=filename,
                level=san_level.value,
                result=None,
                processing_time_ms=processing_time_ms,
                source="mcp",
                error=str(exc),
            )
        except Exception:
            logger.debug("Audit logging failed", exc_info=True)
        logger.exception("Pipeline error processing base64 content (%s)", filename)
        return {"error": f"Processing error: {exc}"}

    response: dict = {
        "status": "success",
        "file": filename,
        "findings": _findings_to_dicts(result),
        "summary": result.summary.model_dump(),
    }

    if result.sanitized_content is not None:
        response["sanitized_content_base64"] = base64.b64encode(
            result.sanitized_content
        ).decode()
        response["output_filename"] = result.output_filename

    return response


@mcp.tool()
async def check_pii(
    file_path: str,
    level: str = "strict",
) -> dict:
    """Check a file for PII without sanitizing. Returns findings only — no file is modified.

    Args:
        file_path: Absolute path to the file (PDF, JPEG, or PNG).
        level: "standard" or "strict" (default strict to catch everything).
    """
    path = Path(file_path)
    if err := _validate_file(path):
        return {"error": err}

    san_level = _parse_level(level)
    file_content = path.read_bytes()

    start_time = time.monotonic()
    try:
        result = await asyncio.to_thread(
            _run_pipeline, file_content, path.name, san_level, ResponseFormat.JSON
        )
        processing_time_ms = int((time.monotonic() - start_time) * 1000)
        try:
            log_sanitization(
                file_content=file_content,
                filename=path.name,
                level=san_level.value,
                result=result,
                processing_time_ms=processing_time_ms,
                source="mcp",
            )
        except Exception:
            logger.debug("Audit logging failed", exc_info=True)
    except Exception as exc:
        processing_time_ms = int((time.monotonic() - start_time) * 1000)
        try:
            log_sanitization(
                file_content=file_content,
                filename=path.name,
                level=san_level.value,
                result=None,
                processing_time_ms=processing_time_ms,
                source="mcp",
                error=str(exc),
            )
        except Exception:
            logger.debug("Audit logging failed", exc_info=True)
        logger.exception("Pipeline error processing %s", file_path)
        return {"error": f"Processing error: {exc}"}

    return {
        "status": "success",
        "file": str(path),
        "has_pii": result.summary.total_findings > 0,
        "findings": _findings_to_dicts(result),
        "summary": result.summary.model_dump(),
    }


# ── Resource ─────────────────────────────────────────────────────────


@mcp.resource("saniflow://config")
async def get_config() -> str:
    """Get current saniflow configuration and capabilities."""
    return json.dumps(
        {
            "version": "0.1.0",
            "supported_formats": settings.SUPPORTED_FORMATS,
            "supported_extensions": sorted(_ALLOWED_EXTENSIONS),
            "max_file_size_bytes": settings.MAX_FILE_SIZE,
            "sanitization_levels": [lv.value for lv in SanitizationLevel],
            "response_formats": [rf.value for rf in ResponseFormat],
            "redaction_styles": [rs.value for rs in RedactionStyle],
            "entity_types": [et.value for et in EntityType],
            "confidence_thresholds": {
                "regex": settings.CONFIDENCE_THRESHOLD_REGEX,
                "ner": settings.CONFIDENCE_THRESHOLD_NER,
            },
        },
        indent=2,
    )


# ── Entry point ──────────────────────────────────────────────────────


def main():
    """Entry point for console_scripts and direct invocation."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
