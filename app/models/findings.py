from enum import Enum

from pydantic import BaseModel


class SanitizationLevel(str, Enum):
    STANDARD = "standard"
    STRICT = "strict"


class EntityType(str, Enum):
    PERSON_NAME = "PERSON_NAME"
    DNI_NIE = "DNI_NIE"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    IBAN = "IBAN"
    ADDRESS = "ADDRESS"
    DATE_OF_BIRTH = "DATE_OF_BIRTH"
    FACE = "FACE"
    SIGNATURE = "SIGNATURE"


class ResponseFormat(str, Enum):
    FILE = "file"
    JSON = "json"
    FULL = "full"


class BBox(BaseModel):
    """Bounding box coordinates."""

    x0: float
    y0: float
    x1: float
    y1: float


class Finding(BaseModel):
    """A single PII detection result."""

    entity_type: EntityType
    original_text: str | None = None
    score: float
    page: int | None = None
    bbox: BBox | None = None


class FindingSummary(BaseModel):
    """Aggregated summary of findings."""

    total_findings: int
    by_type: dict[str, int]
    level_applied: SanitizationLevel


class SanitizationResult(BaseModel):
    """Complete result of the sanitization pipeline."""

    findings: list[Finding]
    summary: FindingSummary
    sanitized_content: bytes | None = None
    original_filename: str
    output_filename: str

    model_config = {"arbitrary_types_allowed": True}
