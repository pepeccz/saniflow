from pydantic import BaseModel, Field

from app.models.findings import BBox, EntityType, FindingSummary, SanitizationLevel


class FindingResponse(BaseModel):
    """A single PII entity detected in the document."""

    entity_type: EntityType = Field(
        description="The type of PII entity detected (e.g. `EMAIL`, `PERSON_NAME`).",
    )
    original_text: str | None = Field(
        default=None,
        description="The original text that was detected as PII. May be null for visual detections such as faces or signatures.",
    )
    score: float = Field(
        description="Confidence score of the detection, between 0.0 and 1.0.",
        ge=0.0,
        le=1.0,
    )
    page: int | None = Field(
        default=None,
        description="1-based page number where the entity was found. Null for single-page images.",
    )
    bbox: BBox | None = Field(
        default=None,
        description="Bounding box coordinates (x0, y0, x1, y1) of the detected region, if available.",
    )
    redacted: bool = Field(
        default=True,
        description="Whether this entity was redacted in the output document.",
    )


class SanitizeResponse(BaseModel):
    """JSON response containing detected PII findings and an aggregated summary."""

    findings: list[FindingResponse] = Field(
        description="List of individual PII detections found in the document.",
    )
    summary: FindingSummary = Field(
        description="Aggregated statistics: total findings count, breakdown by entity type, and the sanitization level applied.",
    )


class SanitizeFullResponse(SanitizeResponse):
    """Full response containing findings, summary, and the sanitized file encoded as a base64 string."""

    file: str = Field(
        description="The sanitized document encoded as a base64 string. Decode to obtain the binary file.",
    )


class BatchFileResult(BaseModel):
    """Result of sanitizing a single file within a batch request."""

    filename: str = Field(
        description="Original filename of the uploaded file.",
    )
    status: str = Field(
        description="Processing status: `success` or `error`.",
    )
    findings: list[FindingResponse] | None = Field(
        default=None,
        description="List of PII detections found in the document. Null on error.",
    )
    summary: FindingSummary | None = Field(
        default=None,
        description="Aggregated statistics for this file. Null on error.",
    )
    file: str | None = Field(
        default=None,
        description="Base64-encoded sanitized document (only when response_format is `file` or `full`).",
    )
    error: str | None = Field(
        default=None,
        description="Error message if processing failed for this file.",
    )


class BatchSanitizeResponse(BaseModel):
    """Response containing per-file results for a batch sanitization request."""

    results: list[BatchFileResult] = Field(
        description="Per-file sanitization results.",
    )
    total_files: int = Field(
        description="Total number of files in the batch.",
    )
    successful: int = Field(
        description="Number of files processed successfully.",
    )
    failed: int = Field(
        description="Number of files that failed processing.",
    )


class HealthResponse(BaseModel):
    """Health check response indicating service status."""

    status: str = Field(
        description="Current health status of the service (e.g. `healthy`).",
    )
    version: str = Field(
        description="Semantic version of the running Saniflow instance.",
    )


class ErrorResponse(BaseModel):
    """Standard error response returned for all 4xx and 5xx status codes."""

    detail: str = Field(
        description="Human-readable description of the error.",
    )
    error_code: str | None = Field(
        default=None,
        description="Optional machine-readable error code for programmatic handling.",
    )
