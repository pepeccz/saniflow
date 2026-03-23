"""API routes for the Saniflow sanitization pipeline."""

from __future__ import annotations

import base64
import logging
import time
from io import BytesIO

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import StreamingResponse
from starlette.concurrency import run_in_threadpool

from app.audit import log_sanitization
from app.api.auth import require_api_key
from app.api.rate_limit import check_rate_limit
from app.api.schemas import (
    BatchFileResult,
    BatchSanitizeResponse,
    ErrorResponse,
    FindingResponse,
    SanitizeFullResponse,
    SanitizeResponse,
)
from app.config import settings
from app.metrics import metrics
from app.models.findings import (
    EntityType,
    RedactionStyle,
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


def _validate_redaction_style(style: str) -> RedactionStyle:
    """Raise 422 if style is not a valid RedactionStyle."""
    try:
        return RedactionStyle(style)
    except ValueError:
        valid = [e.value for e in RedactionStyle]
        raise HTTPException(
            status_code=422,
            detail=f"Invalid redaction style: '{style}'. Must be one of: {valid}",
        )


def _parse_redact_entities(entities: str) -> list[str] | None:
    """Parse comma-separated entity types. Returns None if empty (= redact all)."""
    if not entities or not entities.strip():
        return None
    names = [e.strip() for e in entities.split(",") if e.strip()]
    if not names:
        return None
    valid_values = {et.value for et in EntityType}
    for name in names:
        if name not in valid_values:
            raise HTTPException(
                status_code=422,
                detail=f"Invalid entity type: '{name}'. Must be one of: {sorted(valid_values)}",
            )
    return names


def _build_findings_response(result: SanitizationResult) -> list[FindingResponse]:
    """Convert pipeline findings to API response models."""
    return [
        FindingResponse(
            entity_type=f.entity_type,
            original_text=f.original_text,
            score=f.score,
            page=f.page,
            bbox=f.bbox,
            redacted=f.redacted,
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
    tags=["Sanitization"],
    summary="Sanitize a document by detecting and redacting PII",
    response_description=(
        "The sanitized file as a download (default), a JSON findings report, "
        "or both — depending on the chosen `response_format`."
    ),
    responses={
        200: {
            "description": "Sanitized result returned successfully.",
            "content": {
                "application/json": {
                    "example": {
                        "findings": [
                            {
                                "entity_type": "EMAIL",
                                "original_text": "user@example.com",
                                "score": 0.95,
                                "page": 1,
                                "bbox": None,
                                "redacted": True,
                            }
                        ],
                        "summary": {
                            "total_findings": 1,
                            "by_type": {"EMAIL": 1},
                            "level_applied": "standard",
                        },
                    }
                },
                "application/pdf": {},
                "image/jpeg": {},
                "image/png": {},
            },
        },
        401: {"model": ErrorResponse, "description": "Invalid or missing API key."},
        413: {"model": ErrorResponse, "description": "File exceeds the maximum allowed size."},
        415: {
            "model": ErrorResponse,
            "description": (
                "Unsupported file type. Accepted formats: `application/pdf`, "
                "`image/jpeg`, `image/png`."
            ),
        },
        422: {
            "model": ErrorResponse,
            "description": (
                "Validation error — invalid sanitization level, response format, "
                "redaction style, entity type, or the uploaded file is corrupted."
            ),
        },
        429: {"model": ErrorResponse, "description": "Rate limit exceeded. Retry after the interval in `X-RateLimit-Reset`."},
        500: {"model": ErrorResponse, "description": "Internal processing error."},
    },
    dependencies=[Depends(require_api_key), Depends(check_rate_limit)],
)
async def sanitize(
    request: Request,
    file: UploadFile,
    level: str = Form(
        default="standard",
        description=(
            "Sanitization level controlling detection sensitivity. "
            "`standard` covers common PII; `strict` applies aggressive detection. "
            "Allowed values: `standard`, `strict`."
        ),
    ),
    response_format: str = Form(
        default="file",
        description=(
            "Controls the shape of the response. "
            "`file` returns the sanitized document as a download. "
            "`json` returns only the findings report. "
            "`full` returns both the findings and the base64-encoded file. "
            "Allowed values: `file`, `json`, `full`."
        ),
    ),
    redaction_style: str = Form(
        default="black",
        description=(
            "Visual style used to redact detected PII regions. "
            "`black` fills with a solid black box. "
            "`blur` applies a Gaussian blur. "
            "`placeholder` replaces text with a label (e.g. `[REDACTED]`). "
            "Allowed values: `black`, `blur`, `placeholder`."
        ),
    ),
    redact_entities: str = Form(
        default="",
        description=(
            "Comma-separated list of entity types to redact. "
            "When empty, all detected entities are redacted. "
            "Allowed values: `PERSON_NAME`, `DNI_NIE`, `EMAIL`, `PHONE`, "
            "`IBAN`, `ADDRESS`, `DATE_OF_BIRTH`, `FACE`, `SIGNATURE`."
        ),
    ),
) -> StreamingResponse | SanitizeResponse | SanitizeFullResponse:
    """Sanitize a document by detecting and redacting personally identifiable information (PII).

    Upload a PDF, JPEG, or PNG file and receive the sanitized output. The pipeline
    extracts text and visual elements, runs PII detection (NLP-based and pattern-based
    recognizers), and redacts the identified entities according to the chosen style.

    **Supported file types:** `application/pdf`, `image/jpeg`, `image/png`

    **Response formats:**
    - `file` (default) — returns the sanitized document as a binary download
    - `json` — returns a JSON object with detected findings and summary statistics
    - `full` — returns findings, summary, and the sanitized file as a base64-encoded string

    **Redaction styles:**
    - `black` (default) — solid black box over PII regions
    - `blur` — Gaussian blur applied to PII regions
    - `placeholder` — text replaced with a descriptive label

    **Selective redaction:**
    Use `redact_entities` to limit redaction to specific entity types.
    When omitted or empty, all detected entity types are redacted.
    """
    # --- Validate inputs (fail fast) ---
    content_type = _validate_content_type(file.content_type)
    validated_level = _validate_level(level)
    validated_format = _validate_response_format(response_format)
    validated_style = _validate_redaction_style(redaction_style)
    parsed_entities = _parse_redact_entities(redact_entities)

    # Read file content and validate size
    file_content = await file.read()
    _validate_file_size(len(file_content))

    filename = file.filename or "document"

    # --- Process through pipeline ---
    start_time = time.monotonic()
    try:
        pipeline = SanitizationPipeline()
        result: SanitizationResult = await run_in_threadpool(
            pipeline.process,
            file_content=file_content,
            filename=filename,
            level=validated_level,
            response_format=validated_format,
            redaction_style=validated_style,
            redact_entities=parsed_entities,
        )
        processing_time_ms = int((time.monotonic() - start_time) * 1000)
        try:
            log_sanitization(
                file_content=file_content,
                filename=filename,
                level=validated_level.value,
                result=result,
                processing_time_ms=processing_time_ms,
                source="api",
                client_ip=request.client.host if request.client else None,
            )
        except Exception:
            logger.debug("Audit logging failed", exc_info=True)
        metrics.record_success(processing_time_ms, result.summary.by_type)
    except ValueError as exc:
        # Corrupt / unreadable files raise ValueError from extractors
        processing_time_ms = int((time.monotonic() - start_time) * 1000)
        try:
            log_sanitization(
                file_content=file_content,
                filename=filename,
                level=validated_level.value,
                result=None,
                processing_time_ms=processing_time_ms,
                source="api",
                client_ip=request.client.host if request.client else None,
                error=str(exc),
            )
        except Exception:
            logger.debug("Audit logging failed", exc_info=True)
        metrics.record_failure(processing_time_ms)
        logger.warning("File processing failed (corrupt/unreadable): %s", exc)
        raise HTTPException(
            status_code=422,
            detail="File is corrupted or unreadable",
        )
    except HTTPException:
        raise
    except Exception:
        processing_time_ms = int((time.monotonic() - start_time) * 1000)
        try:
            log_sanitization(
                file_content=file_content,
                filename=filename,
                level=validated_level.value,
                result=None,
                processing_time_ms=processing_time_ms,
                source="api",
                client_ip=request.client.host if request.client else None,
                error="Internal processing error",
            )
        except Exception:
            logger.debug("Audit logging failed", exc_info=True)
        metrics.record_failure(processing_time_ms)
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

    return StreamingResponse(
        content=BytesIO(result.sanitized_content),
        media_type=content_type,
        headers={
            "Content-Disposition": f'attachment; filename="{output_filename}"',
        },
    )


@router.get(
    "/metrics",
    tags=["Health"],
    summary="Get processing metrics",
    response_description="Current in-memory processing metrics (resets on restart).",
)
async def get_metrics() -> dict:
    """Return current processing metrics.

    This endpoint does **not** require authentication — it exposes
    operational counters only, never PII.
    """
    return metrics.snapshot()


@router.post(
    "/sanitize/batch",
    response_model=BatchSanitizeResponse,
    tags=["Sanitization"],
    summary="Sanitize multiple documents in a single request",
    response_description="Per-file sanitization results with aggregated counts.",
    responses={
        200: {"description": "Batch processed successfully (individual files may still have errors)."},
        401: {"model": ErrorResponse, "description": "Invalid or missing API key."},
        422: {
            "model": ErrorResponse,
            "description": "Batch exceeds maximum size, or invalid parameter values.",
        },
        429: {"model": ErrorResponse, "description": "Rate limit exceeded."},
    },
    dependencies=[Depends(require_api_key), Depends(check_rate_limit)],
)
async def sanitize_batch(
    request: Request,
    files: list[UploadFile] = File(
        ...,
        description="One or more files to sanitize (PDF, JPEG, or PNG).",
    ),
    level: str = Form(
        default="standard",
        description="Sanitization level: `standard` or `strict`.",
    ),
    response_format: str = Form(
        default="json",
        description=(
            "Controls the shape of per-file results. "
            "`json` returns findings only. "
            "`file` or `full` includes base64-encoded sanitized content."
        ),
    ),
    redaction_style: str = Form(
        default="black",
        description="Redaction style: `black`, `blur`, or `placeholder`.",
    ),
    redact_entities: str = Form(
        default="",
        description="Comma-separated entity types to redact. Empty = all.",
    ),
) -> BatchSanitizeResponse:
    """Sanitize multiple documents in a single batch request.

    Each file is processed independently — if one file fails, the remaining
    files are still processed. Results include per-file status, findings,
    and optional base64-encoded sanitized content.
    """
    # --- Validate batch size ---
    if len(files) > settings.MAX_BATCH_SIZE:
        raise HTTPException(
            status_code=422,
            detail=f"Batch exceeds maximum size of {settings.MAX_BATCH_SIZE} files",
        )

    # --- Validate shared params (fail fast) ---
    validated_level = _validate_level(level)
    validated_format = _validate_response_format(response_format)
    validated_style = _validate_redaction_style(redaction_style)
    parsed_entities = _parse_redact_entities(redact_entities)

    # For batch, we always return JSON with optional base64 content.
    # Map "file" format to "full" so the pipeline produces sanitized bytes.
    pipeline_format = (
        ResponseFormat.FULL if validated_format == ResponseFormat.FILE else validated_format
    )

    results: list[BatchFileResult] = []
    successful = 0
    failed = 0

    for upload_file in files:
        filename = upload_file.filename or "document"
        start_time = time.monotonic()

        try:
            # Validate content type
            _validate_content_type(upload_file.content_type)

            # Read and validate size
            file_content = await upload_file.read()
            _validate_file_size(len(file_content))

            # Process
            batch_pipeline = SanitizationPipeline()
            file_result: SanitizationResult = await run_in_threadpool(
                batch_pipeline.process,
                file_content=file_content,
                filename=filename,
                level=validated_level,
                response_format=pipeline_format,
                redaction_style=validated_style,
                redact_entities=parsed_entities,
            )
            processing_time_ms = int((time.monotonic() - start_time) * 1000)

            # Audit log for this file
            try:
                log_sanitization(
                    file_content=file_content,
                    filename=filename,
                    level=validated_level.value,
                    result=file_result,
                    processing_time_ms=processing_time_ms,
                    source="api",
                    client_ip=request.client.host if request.client else None,
                )
            except Exception:
                logger.debug("Audit logging failed for %s", filename, exc_info=True)

            # Build per-file result
            findings = _build_findings_response(file_result)
            encoded_file = None
            if validated_format in (ResponseFormat.FILE, ResponseFormat.FULL) and file_result.sanitized_content is not None:
                encoded_file = base64.b64encode(file_result.sanitized_content).decode("ascii")

            results.append(BatchFileResult(
                filename=filename,
                status="success",
                findings=findings,
                summary=file_result.summary,
                file=encoded_file,
            ))
            successful += 1

        except HTTPException as exc:
            processing_time_ms = int((time.monotonic() - start_time) * 1000)
            try:
                log_sanitization(
                    file_content=b"",
                    filename=filename,
                    level=validated_level.value,
                    result=None,
                    processing_time_ms=processing_time_ms,
                    source="api",
                    client_ip=request.client.host if request.client else None,
                    error=exc.detail,
                )
            except Exception:
                logger.debug("Audit logging failed for %s", filename, exc_info=True)

            results.append(BatchFileResult(
                filename=filename,
                status="error",
                error=exc.detail,
            ))
            failed += 1

        except Exception as exc:
            processing_time_ms = int((time.monotonic() - start_time) * 1000)
            error_msg = str(exc) if isinstance(exc, ValueError) else "Internal processing error"
            try:
                log_sanitization(
                    file_content=b"",
                    filename=filename,
                    level=validated_level.value,
                    result=None,
                    processing_time_ms=processing_time_ms,
                    source="api",
                    client_ip=request.client.host if request.client else None,
                    error=error_msg,
                )
            except Exception:
                logger.debug("Audit logging failed for %s", filename, exc_info=True)

            results.append(BatchFileResult(
                filename=filename,
                status="error",
                error=error_msg,
            ))
            failed += 1

    return BatchSanitizeResponse(
        results=results,
        total_files=len(files),
        successful=successful,
        failed=failed,
    )
