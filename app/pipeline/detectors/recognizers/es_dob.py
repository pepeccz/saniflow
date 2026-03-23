"""Custom Presidio recognizer for Spanish dates of birth.

Detects date patterns (dd/mm/yyyy, dd-mm-yyyy, dd.mm.yyyy) ONLY when
they appear near birth-related context words.  The low base score (0.3)
ensures that generic dates (invoice dates, policy dates, etc.) are NOT
flagged — context boosting is required for a match to exceed the
confidence threshold.
"""

from __future__ import annotations

from presidio_analyzer import Pattern, PatternRecognizer


class EsDateOfBirthRecognizer(PatternRecognizer):
    """Recognizer for dates of birth in Spanish documents."""

    PATTERNS = [
        Pattern(
            name="ES_DATE_OF_BIRTH",
            regex=r"\b\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4}\b",
            score=0.3,
        ),
    ]

    CONTEXT = [
        "nacimiento",
        "fecha nacimiento",
        "f. nac",
        "nacido",
        "nacida",
        "fecha de nacimiento",
        "born",
        "f.nac",
        "fec. nacimiento",
        "fec nacimiento",
    ]

    def __init__(self, supported_language: str = "es") -> None:
        super().__init__(
            supported_entity="ES_DATE_OF_BIRTH",
            supported_language=supported_language,
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            name="EsDateOfBirthRecognizer",
        )
