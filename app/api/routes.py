"""API routes for the Saniflow sanitization pipeline."""

from __future__ import annotations

import base64
import json
import logging
from io import BytesIO

from fastapi import APIRouter, HTTPException, UploadFile
from fastapi.responses import StreamingResponse

from app.api.schemas import (
    ErrorResponse,
    FindingResponse,
    SanitizeFullResponse,
    SanitizeResponse,
)
from app.config import settings
from app.models.findings import (
    ResponseFormat,
    SanitizationLevel,
    SanitizationResult,
)
from app.pipeline.orchestrator import SanitizationPipeline

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1")

# Content-type to file extension mapping for Content-Disposition header
_MIME_TO_EXT: dict[str, str] = {
    "application/pdf": ".pdf",
    "image/jpeg": ".jpg",
    "image/png": ".png",
}


def _validate_file_size(content_length: int) -> None:
    """Raise 413 if file exceeds configured max size."""
    if content_length > settings.MAX_FILE_SIZE:
        limit_mb = settings.MAX_FILE_SIZE / (1024 * 1024)
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds maximum size of {limit_mb:.0f} MB",
        )


def _validate_content_type(content_type: str | None) -> str:
    """Raise 415 if content type is not supported. Returns validated type."""
    if content_type is None or content_type not in settings.SUPPORTED_FORMATS:
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported file type: {content_type}",
        )
    return content_type


def _validate_level(level: str) -> SanitizationLevel:
    """Raise 422 if level is not a valid SanitizationLevel."""
    try:
        return SanitizationLevel(level)
    except ValueError:
        valid = [e.value for e in SanitizationLevel]
        raise HTTPException(
            status_code=422,
            detail=f"Invalid sanitization level: '{level}'. Must be one of: {valid}",
        )


def _validate_response_format(response_format: str) -> ResponseFormat:
    """Raise 422 if response_format is not a valid ResponseFormat."""
    try:
        return ResponseFormat(response_format)
    except ValueError:
        valid = [e.value for e in ResponseFormat]
        raise HTTPException(
            status_code=422,
            detail=f"Invalid response format: '{response_format}'. Must be one of: {valid}",
        )


def _build_findings_response(result: SanitizationResult) -> list[FindingResponse]:
    """Convert pipeline findings to API response models."""
    return [
        FindingResponse(
            entity_type=f.entity_type,
            original_text=f.original_text,
            score=f.score,
            page=f.page,
            bbox=f.bbox,
        )
        for f in result.findings
    ]


def _build_sanitized_filename(original: str) -> str:
    """Generate the output filename: original_sanitized.ext."""
    # The pipeline already provides output_filename, but we keep this as fallback
    if "." in original:
        name, ext = original.rsplit(".", 1)
        return f"{name}_sanitized.{ext}"
    return f"{original}_sanitized"


@router.post(
    "/sanitize",
    response_model=None,
    responses={
        413: {"model": ErrorResponse, "description": "File too large"},
        415: {"model": ErrorResponse, "description": "Unsupported file type"},
        422: {"model": ErrorResponse, "description": "Invalid input or corrupted file"},
        500: {"model": ErrorResponse, "description": "Internal processing error"},
    },
)
async def sanitize(
    file: UploadFile,
    level: str = "standard",
    response_format: str = "file",
) -> StreamingResponse | SanitizeResponse | SanitizeFullResponse:
    """Sanitize a document by detecting and redacting PII.

    Accepts PDF, JPEG, or PNG files. Returns the sanitized file, a JSON
    findings report, or both, depending on *response_format*.
    """
    # --- Validate inputs (fail fast) ---
    content_type = _validate_content_type(file.content_type)
    validated_level = _validate_level(level)
    validated_format = _validate_response_format(response_format)

    # Read file content and validate size
    file_content = await file.read()
    _validate_file_size(len(file_content))

    filename = file.filename or "document"

    # --- Process through pipeline ---
    try:
        pipeline = SanitizationPipeline()
        result: SanitizationResult = pipeline.process(
            file_content=file_content,
            filename=filename,
            level=validated_level,
            response_format=validated_format,
        )
    except ValueError as exc:
        # Corrupt / unreadable files raise ValueError from extractors
        logger.warning("File processing failed (corrupt/unreadable): %s", exc)
        raise HTTPException(
            status_code=422,
            detail="File is corrupted or unreadable",
        )
    except HTTPException:
        raise
    except Exception:
        logger.exception("Unexpected error during sanitization")
        raise HTTPException(
            status_code=500,
            detail="Internal processing error",
        )

    # --- Build response based on format ---
    findings = _build_findings_response(result)

    if validated_format == ResponseFormat.JSON:
        return SanitizeResponse(
            findings=findings,
            summary=result.summary,
        )

    if validated_format == ResponseFormat.FULL:
        encoded_file = ""
        if result.sanitized_content is not None:
            encoded_file = base64.b64encode(result.sanitized_content).decode("ascii")
        return SanitizeFullResponse(
            findings=findings,
            summary=result.summary,
            file=encoded_file,
        )

    # Default: ResponseFormat.FILE — stream sanitized file back
    if result.sanitized_content is None:
        logger.error("Pipeline returned no sanitized content for file format response")
        raise HTTPException(
            status_code=500,
            detail="Internal processing error",
        )

    output_filename = result.output_filename or _build_sanitized_filename(filename)

    # Build compact findings JSON for the header
    findings_json = json.dumps(
        [f.model_dump(exclude_none=True) for f in findings],
        separators=(",", ":"),
        ensure_ascii=True,
    )

    return StreamingResponse(
        content=BytesIO(result.sanitized_content),
        media_type=content_type,
        headers={
            "Content-Disposition": f'attachment; filename="{output_filename}"',
            "X-Saniflow-Findings": findings_json,
        },
    )
