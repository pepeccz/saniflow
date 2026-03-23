"""Custom Presidio recognizer for Spanish person names.

Handles formats common in Spanish insurance documents:
- APELLIDO APELLIDO, NOMBRE (inverted formal format)
- APELLIDO, NOMBRE SEGUNDO_NOMBRE
- Two or more consecutive capitalized words near context keywords

Works in tandem with the title-case pre-processing in TextPiiDetector
to handle ALL-CAPS input that spaCy cannot parse.
"""

from __future__ import annotations

from presidio_analyzer import Pattern, PatternRecognizer

PERSON_DENY_LIST: frozenset[str] = frozenset({
    "condiciones",
    "generales",
    "particulares",
    "seguro",
    "seguros",
    "mutua",
    "aseguradora",
    "póliza",
    "tomador",
    "mediador",
    "beneficiario",
    "siniestro",
    "prima",
    "cobertura",
    "prestación",
    "indemnización",
    "franquicia",
    "suplemento",
    "anexo",
    "artículo",
    "reglamento",
    "legislación",
    "jurisdicción",
    "tribunal",
    "juzgado",
    "cláusula",
    "boletín",
})


class EsPersonRecognizer(PatternRecognizer):
    """Recognizer for Spanish person names in formal/inverted formats."""

    PATTERNS = [
        # APELLIDO APELLIDO, NOMBRE (with optional second name)
        Pattern(
            name="ES_PERSON_INVERTED",
            regex=(
                r"(?i)\b[A-ZÁÉÍÓÚÑ][a-záéíóúñA-ZÁÉÍÓÚÑ]+"
                r"\s+[A-ZÁÉÍÓÚÑ][a-záéíóúñA-ZÁÉÍÓÚÑ]+"
                r",\s*[A-ZÁÉÍÓÚÑ][a-záéíóúñA-ZÁÉÍÓÚÑ]+"
                r"(?:\s+[A-ZÁÉÍÓÚÑ][a-záéíóúñA-ZÁÉÍÓÚÑ]+)?\b"
            ),
            score=0.7,
        ),
    ]

    CONTEXT = [
        "tomador",
        "asegurado",
        "beneficiario",
        "titular",
        "nombre",
        "sr",
        "sra",
        "don",
        "doña",
        "d.",
        "dña",
        "firmante",
        "representante",
        "colaborador",
        "mediador",
        "contratante",
    ]

    def __init__(self, supported_language: str = "es") -> None:
        super().__init__(
            supported_entity="PERSON",
            supported_language=supported_language,
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            name="EsPersonRecognizer",
        )
