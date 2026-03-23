"""Custom Presidio recognizer for Spanish IBANs.

Handles formats including partial/masked IBANs common in real documents:
- ES91 2100 0418 4502 0005 1332  (full, standard grouping)
- ES9121000418450200051332        (full, no spaces)
- ES90 0182 2752 37 020167****   (masked, non-standard grouping)
- IBAN: ES91 2100 0418 4502 0005 1332  (with label prefix)

Unlike Presidio's built-in IbanRecognizer (which uses mod-97 checksum
validation), this recognizer uses pattern matching only — so it catches
partial/masked IBANs that would fail checksum validation.
"""

from __future__ import annotations

from presidio_analyzer import Pattern, PatternRecognizer


class EsIbanRecognizer(PatternRecognizer):
    """Recognizer for Spanish IBANs, including partial/masked variants."""

    PATTERNS = [
        # Full Spanish IBAN with optional spaces/dashes (24 chars after ES)
        Pattern(
            name="ES_IBAN_FULL",
            regex=(
                r"(?i)\bES\s?\d{2}[\s\-]?\d{4}[\s\-]?\d{4}"
                r"[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"
            ),
            score=0.9,
        ),
        # IBAN with label prefix (most specific context)
        Pattern(
            name="ES_IBAN_LABELED",
            regex=r"(?i)(?:IBAN[:\s]*)\bES\s?\d{2}[\s\-]?[\d\s\-\*]{12,24}\b",
            score=0.85,
        ),
        # Partial/masked IBAN (with * or X for masked digits)
        Pattern(
            name="ES_IBAN_MASKED",
            regex=(
                r"(?i)\bES\s?\d{2}[\s\-]?\d{4}[\s\-]?\d{4}"
                r"[\s\-]?[\d\s\-]{2,10}[\d\*Xx]{2,8}\b"
            ),
            score=0.7,
        ),
    ]

    CONTEXT = [
        "iban",
        "cuenta",
        "bancaria",
        "banco",
        "transferencia",
        "domiciliación",
        "domiciliacion",
        "cuenta corriente",
        "nº cuenta",
    ]

    def __init__(self, supported_language: str = "es") -> None:
        super().__init__(
            supported_entity="IBAN_CODE",
            supported_language=supported_language,
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            name="EsIbanRecognizer",
        )
