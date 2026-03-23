from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from app.models.extraction import ExtractionResult
    from app.models.findings import Finding, SanitizationLevel


class Detector(Protocol):
    """Protocol for PII detectors.

    Implementations analyse an ExtractionResult and return a list of
    Finding objects, optionally adjusting behaviour based on the
    requested sanitization level.
    """

    def detect(
        self,
        extraction_result: ExtractionResult,
        level: SanitizationLevel,
    ) -> list[Finding]: ...
