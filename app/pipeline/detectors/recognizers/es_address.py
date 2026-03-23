"""Custom Presidio recognizer for Spanish postal addresses.

Handles patterns like:
- Calle Mayor 15, 28001 Madrid
- C. Gran Vía, 42
- Av. de la Constitución 10, 3ºB
- Avda. Diagonal, 123
- Plaza España 1
- Paseo de Gracia 55, 08007 Barcelona
- Pº del Prado, 28
"""

from __future__ import annotations

from presidio_analyzer import Pattern, PatternRecognizer

# Street type prefixes (case-insensitive via Presidio's regex flags)
_STREET_TYPES = (
    r"(?:"
    r"[Cc](?:alle|/)"          # Calle, C/
    r"|[Cc]\."                  # C.
    r"|[Aa]v(?:da)?\.?"         # Av, Av., Avda, Avda.
    r"|[Aa]venida"              # Avenida
    r"|[Pp]laza"                # Plaza
    r"|[Pp](?:za?)?\.?"         # Pl., Pza., Pz.
    r"|[Pp]aseo"                # Paseo
    r"|[Pp]º"                   # Pº
    r"|[Cc]amino"               # Camino
    r"|[Rr]onda"                # Ronda
    r"|[Tt]ravesía"             # Travesía
    r"|[Cc]arrera"              # Carrera
    r")"
)

# The street name (3-40 chars) followed by a number, optional floor/door,
# optional postal code, optional city name.
_STREET_BODY = (
    r"\s+.{3,40}?"             # street name
    r",?\s*\d{1,4}"            # street number
    r"(?:\s*[-,]\s*\d{1,3}[ºª]?\s*[A-Za-z]?)?"  # optional floor/door
    r"(?:\s*,?\s*\d{5})?"      # optional postal code (5 digits)
    r"(?:\s*,?\s*[A-ZÁÉÍÓÚÑ][a-záéíóúñ]+)?"  # optional city
)

_FULL_PATTERN = _STREET_TYPES + _STREET_BODY


class EsAddressRecognizer(PatternRecognizer):
    """Recognizer for Spanish postal addresses.

    Scored at 0.5 because address regex is inherently fuzzy —
    this is a SHOULD-level detection per the spec.
    """

    PATTERNS = [
        Pattern(
            name="ES_ADDRESS",
            regex=_FULL_PATTERN,
            score=0.5,
        ),
    ]

    CONTEXT = [
        "dirección",
        "direccion",
        "domicilio",
        "residencia",
        "vive en",
        "domiciliado",
        "domiciliada",
        "sito en",
        "ubicado",
        "ubicación",
        "ubicacion",
    ]

    def __init__(self, supported_language: str = "es") -> None:
        super().__init__(
            supported_entity="ES_ADDRESS",
            supported_language=supported_language,
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            name="EsAddressRecognizer",
        )
