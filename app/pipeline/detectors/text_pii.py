"""Text PII detector powered by Presidio Analyzer.

Initialises the Presidio AnalyzerEngine once (lazy singleton) and maps
Presidio entity types to our internal EntityType enum.  Character offsets
from Presidio are resolved to page numbers and bounding boxes via the
SpanMap attached to the ExtractionResult.
"""

from __future__ import annotations

import logging
from typing import ClassVar

from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider

from app.config import settings
from app.models.extraction import ExtractionResult
from app.models.findings import BBox, EntityType, Finding, SanitizationLevel
from app.pipeline.detectors.recognizers.es_address import EsAddressRecognizer
from app.pipeline.detectors.recognizers.es_phone import EsPhoneRecognizer

logger = logging.getLogger(__name__)

# ── Entity type mapping: Presidio name → our EntityType ──────────────

_PRESIDIO_TO_ENTITY: dict[str, EntityType] = {
    "PERSON": EntityType.PERSON_NAME,
    "ES_NIF": EntityType.DNI_NIE,
    "ES_NIE": EntityType.DNI_NIE,
    "EMAIL_ADDRESS": EntityType.EMAIL,
    "PHONE_NUMBER": EntityType.PHONE,
    "IBAN_CODE": EntityType.IBAN,
    "ES_ADDRESS": EntityType.ADDRESS,
}

# ── Entities per sanitization level ──────────────────────────────────

_STANDARD_ENTITIES: list[str] = [
    "PERSON",
    "ES_NIF",
    "ES_NIE",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "IBAN_CODE",
]

_STRICT_ENTITIES: list[str] = [
    *_STANDARD_ENTITIES,
    "ES_ADDRESS",
]


class TextPiiDetector:
    """Detects text-based PII using Presidio with Spanish NLP support.

    The underlying AnalyzerEngine is created lazily on first use and
    reused for all subsequent calls (module-level singleton).
    """

    _analyzer: ClassVar[AnalyzerEngine | None] = None

    # ── Singleton initialisation ─────────────────────────────────────

    @classmethod
    def _get_analyzer(cls) -> AnalyzerEngine:
        """Return the shared AnalyzerEngine, creating it on first call."""
        if cls._analyzer is not None:
            return cls._analyzer

        logger.info("Initialising Presidio AnalyzerEngine (spaCy model: %s)…", settings.SPACY_MODEL)

        nlp_config = {
            "nlp_engine_name": "spacy",
            "models": [
                {
                    "lang_code": "es",
                    "model_name": settings.SPACY_MODEL,
                },
            ],
        }
        nlp_engine = NlpEngineProvider(nlp_configuration=nlp_config).create_engine()

        analyzer = AnalyzerEngine(
            nlp_engine=nlp_engine,
            supported_languages=["es"],
        )

        # Register custom Spanish recognizers
        analyzer.registry.add_recognizer(EsPhoneRecognizer(supported_language="es"))
        analyzer.registry.add_recognizer(EsAddressRecognizer(supported_language="es"))

        cls._analyzer = analyzer
        logger.info("Presidio AnalyzerEngine ready.")
        return cls._analyzer

    # ── Detection ────────────────────────────────────────────────────

    def detect(
        self,
        extraction_result: ExtractionResult,
        level: SanitizationLevel,
    ) -> list[Finding]:
        """Run Presidio analysis on the extracted text and resolve locations.

        Args:
            extraction_result: The output of an Extractor, containing
                ``text`` and ``span_map`` for coordinate resolution.
            level: ``standard`` analyses core PII entities; ``strict``
                adds ADDRESS detection.

        Returns:
            A list of Finding objects with entity type, confidence score,
            page number and bounding box (when available).
        """
        text = extraction_result.text
        if not text or not text.strip():
            return []

        analyzer = self._get_analyzer()

        entities = _STRICT_ENTITIES if level == SanitizationLevel.STRICT else _STANDARD_ENTITIES

        presidio_results = analyzer.analyze(
            text=text,
            language="es",
            entities=entities,
            score_threshold=settings.CONFIDENCE_THRESHOLD_NER,
        )

        findings: list[Finding] = []
        for result in presidio_results:
            entity_type = _PRESIDIO_TO_ENTITY.get(result.entity_type)
            if entity_type is None:
                logger.debug("Skipping unmapped Presidio entity type: %s", result.entity_type)
                continue

            # Resolve character offsets to page + bbox via SpanMap.
            # resolve() returns list[tuple[int, tuple[float, float, float, float]]].
            # We take the first overlapping span's location.
            page: int | None = None
            bbox: BBox | None = None

            locations = extraction_result.span_map.resolve(result.start, result.end)
            if locations:
                page, raw_bbox = locations[0]
                bbox = BBox(
                    x0=raw_bbox[0],
                    y0=raw_bbox[1],
                    x1=raw_bbox[2],
                    y1=raw_bbox[3],
                )

            # Extract the original text fragment (useful for debugging/logging)
            original_text = text[result.start : result.end]

            findings.append(
                Finding(
                    entity_type=entity_type,
                    original_text=original_text,
                    score=result.score,
                    page=page,
                    bbox=bbox,
                ),
            )

        logger.info(
            "TextPiiDetector found %d entities (level=%s)",
            len(findings),
            level.value,
        )
        return findings
