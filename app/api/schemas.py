from pydantic import BaseModel

from app.models.findings import BBox, EntityType, FindingSummary, SanitizationLevel


class FindingResponse(BaseModel):
    """Single finding in the API response."""

    entity_type: EntityType
    original_text: str | None = None
    score: float
    page: int | None = None
    bbox: BBox | None = None


class SanitizeResponse(BaseModel):
    """Response for JSON and full response formats."""

    findings: list[FindingResponse]
    summary: FindingSummary


class SanitizeFullResponse(SanitizeResponse):
    """Full response including base64-encoded sanitized file."""

    file: str  # base64-encoded sanitized file


class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    version: str


class ErrorResponse(BaseModel):
    """Standard error response."""

    detail: str
    error_code: str | None = None
