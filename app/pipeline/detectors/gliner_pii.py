"""GLiNER-based PII detector — optional second detection layer.

Uses a zero-shot NER transformer model to detect PII entities in text.
The ``gliner`` package is an OPTIONAL dependency; all imports are deferred
so that the package is never loaded when ``GLINER_ENABLED`` is ``False``
or when it is not installed.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

from app.config import settings
from app.models.findings import EntityType, Finding

logger = logging.getLogger(__name__)

# ── Label mapping: GLiNER label → our EntityType ─────────────────────

GLINER_LABEL_MAP: dict[str, EntityType] = {
    "person": EntityType.PERSON_NAME,
    "email": EntityType.EMAIL,
    "phone number": EntityType.PHONE,
    "iban": EntityType.IBAN,
    "date of birth": EntityType.DATE_OF_BIRTH,
    "address": EntityType.ADDRESS,
    "passport number": EntityType.DNI_NIE,
    "social security number": EntityType.DNI_NIE,
    "credit card number": EntityType.SENSITIVE_DATA,
    "medical condition": EntityType.SENSITIVE_DATA,
    "medication": EntityType.SENSITIVE_DATA,
    "ip address": EntityType.SENSITIVE_DATA,
    "bank account": EntityType.SENSITIVE_DATA,
    "tax identification number": EntityType.SENSITIVE_DATA,
    "driver license": EntityType.SENSITIVE_DATA,
    "vehicle registration": EntityType.SENSITIVE_DATA,
}


# ── Detector ─────────────────────────────────────────────────────────


class GlinerPiiDetector:
    """Detect PII using GLiNER zero-shot NER model.

    The model is loaded lazily on first use (class-level singleton) so
    that it is only downloaded/loaded when actually needed.
    """

    _model: ClassVar[Any] = None

    @classmethod
    def _load_model(cls) -> Any:
        """Return the shared GLiNER model, loading it on first call."""
        if cls._model is not None:
            return cls._model
        try:
            from gliner import GLiNER  # noqa: WPS433 — intentional lazy import

            logger.info("Loading GLiNER model: %s", settings.GLINER_MODEL)
            cls._model = GLiNER.from_pretrained(settings.GLINER_MODEL)
            logger.info("GLiNER model loaded successfully.")
            return cls._model
        except ImportError:
            logger.warning(
                "gliner package not installed. Install with: pip install 'saniflow[gliner]'"
            )
            return None
        except Exception:
            logger.exception("Failed to load GLiNER model.")
            return None

    def detect(self, text: str) -> list[Finding]:
        """Detect PII entities in *text* using GLiNER."""
        model = self._load_model()
        if model is None:
            return []

        try:
            entities = model.predict_entities(
                text, settings.GLINER_LABELS, threshold=settings.GLINER_THRESHOLD,
            )
            return [self._to_finding(e) for e in entities]
        except Exception:
            logger.exception("GLiNER prediction failed.")
            return []

    @staticmethod
    def _to_finding(entity: dict) -> Finding:
        """Convert a raw GLiNER entity dict to a Finding."""
        entity_type = GLINER_LABEL_MAP.get(
            entity["label"].lower(), EntityType.SENSITIVE_DATA,
        )
        return Finding(
            entity_type=entity_type,
            original_text=entity["text"],
            score=round(entity["score"], 2),
        )


# ── Deduplication ────────────────────────────────────────────────────


def merge_findings(
    existing: list[Finding],
    new: list[Finding],
) -> list[Finding]:
    """Merge two finding lists, deduplicating overlapping detections.

    When two findings refer to the same (or overlapping) text span, the
    one with the higher confidence score is kept.
    """
    merged = list(existing)
    for nf in new:
        if nf.original_text is None:
            merged.append(nf)
            continue
        duplicate = False
        for i, ef in enumerate(merged):
            if _is_duplicate(ef, nf):
                # Keep the finding with higher confidence.
                if (nf.score or 0) > (ef.score or 0):
                    merged[i] = nf
                duplicate = True
                break
        if not duplicate:
            merged.append(nf)
    return merged


def _is_duplicate(a: Finding, b: Finding) -> bool:
    """Check if two findings refer to the same text span."""
    if not a.original_text or not b.original_text:
        return False
    a_text = a.original_text.strip().lower()
    b_text = b.original_text.strip().lower()
    # Exact match
    if a_text == b_text:
        return True
    # One contains the other
    if a_text in b_text or b_text in a_text:
        return True
    return False
