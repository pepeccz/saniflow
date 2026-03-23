"""Custom Presidio recognizer for Spanish phone numbers.

Handles formats:
- International with prefix: +34 612 345 678, +34-612-345-678, +34.612.345.678
- Local mobile (6xx): 612 345 678, 612-345-678, 612345678
- Local landline (9xx): 912 345 678, 912-345-678, 912345678
"""

from __future__ import annotations

from presidio_analyzer import Pattern, PatternRecognizer


class EsPhoneRecognizer(PatternRecognizer):
    """Recognizer for Spanish phone numbers."""

    # Patterns ordered by specificity — international prefix gets higher score
    PATTERNS = [
        Pattern(
            name="ES_PHONE_INTL",
            regex=r"\+34[\s.\-]?[69]\d{2}[\s.\-]?\d{3}[\s.\-]?\d{3}",
            score=0.7,
        ),
        Pattern(
            name="ES_PHONE_LOCAL",
            regex=r"\b[69]\d{2}[\s.\-]?\d{3}[\s.\-]?\d{3}\b",
            score=0.5,
        ),
    ]

    CONTEXT = [
        "teléfono",
        "telefono",
        "móvil",
        "movil",
        "llamar",
        "contacto",
        "tel",
        "tfno",
        "telf",
        "número",
        "numero",
    ]

    def __init__(self, supported_language: str = "es") -> None:
        super().__init__(
            supported_entity="PHONE_NUMBER",
            supported_language=supported_language,
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            name="EsPhoneRecognizer",
        )
