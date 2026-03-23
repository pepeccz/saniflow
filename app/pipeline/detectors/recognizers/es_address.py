"""Custom Presidio recognizer for Spanish postal addresses.

Handles patterns like:
- Calle Mayor 15, 28001 Madrid
- C. Gran Vía, 42
- Av. de la Constitución 10, 3ºB
- Avda. Diagonal, 123
- Plaza España 1
- Paseo de Gracia 55, 08007 Barcelona
- Pº del Prado, 28
- URBANIZACION HAZA DEL AGARROBO 50, 29650 MIJAS (MALAGA)
- CALLE ARIBAU, 200 PLANTA 3, 08036 - BARCELONA
- C/ Mayor, 15
- Partida Rural 12, 03700 Dénia

Uses (?i) flag for TRUE case-insensitivity across all patterns.
"""

from __future__ import annotations

from presidio_analyzer import Pattern, PatternRecognizer

# Street type prefixes — (?i) makes the entire pattern case-insensitive
_STREET_TYPES = (
    r"(?:"
    r"c(?:alle|/)"                  # Calle, C/
    r"|c\."                         # C.
    r"|av(?:da)?\.?"                # Av, Av., Avda, Avda.
    r"|avenida"                     # Avenida
    r"|plaza"                       # Plaza
    r"|p(?:za?)?\.?"                # Pl., Pza., Pz.
    r"|paseo"                       # Paseo
    r"|pº"                          # Pº
    r"|camino"                      # Camino
    r"|ronda"                       # Ronda
    r"|traves[ií]a"                 # Travesía / Travesia
    r"|carrera"                     # Carrera
    r"|urbanizaci[oó]n"             # Urbanización / Urbanizacion
    r"|urb\.?"                      # Urb, Urb.
    r"|partida"                     # Partida
    r"|barrio"                      # Barrio
    r"|pol[ií]gono"                 # Polígono / Poligono
    r"|glorieta"                    # Glorieta
    r"|bulevar"                     # Bulevar
    r"|blvd\.?"                     # Blvd, Blvd.
    r")"
)

# Street name + number + optional floor/door + optional postal code + optional city (+ optional province)
_STREET_BODY = (
    r"\s+.{3,50}?"                  # street name (greedy enough for long names)
    r",?\s*\d{1,4}"                 # street number
    r"(?:\s*[-,]\s*(?:planta\s*)?\d{1,3}[ºª]?\s*[a-z]?)?"  # optional floor/door
    r"(?:\s*,?\s*\d{5}\s*[-–]?)?"   # optional postal code (5 digits)
    r"(?:\s*,?\s*[a-záéíóúñ][a-záéíóúñ\s]+"  # optional city
    r"(?:\([a-záéíóúñ][a-záéíóúñ\s]+\))?"     # optional province in parens
    r")?"
)

_FULL_PATTERN = r"(?i)" + _STREET_TYPES + _STREET_BODY

# Second pattern: postal code + city (with optional province)
_POSTAL_CITY_PATTERN = (
    r"(?i)\b\d{5}\s*[-–]?\s*"
    r"[a-záéíóúñ][a-záéíóúñ\s]+"
    r"(?:\([a-záéíóúñ][a-záéíóúñ\s]+\))?"
)


class EsAddressRecognizer(PatternRecognizer):
    """Recognizer for Spanish postal addresses.

    Uses (?i) flag for true case-insensitivity so patterns match
    "CALLE", "Calle", "calle", "URBANIZACION", etc.

    Two patterns:
    - Full address (street type + name + number + optional extras): score 0.5
    - Postal code + city: score 0.4
    """

    PATTERNS = [
        Pattern(
            name="ES_ADDRESS_FULL",
            regex=_FULL_PATTERN,
            score=0.5,
        ),
        Pattern(
            name="ES_ADDRESS_POSTAL_CITY",
            regex=_POSTAL_CITY_PATTERN,
            score=0.4,
        ),
    ]

    CONTEXT = [
        "dirección",
        "direccion",
        "domicilio",
        "residencia",
        "domiciliado",
        "domiciliada",
        "sita en",
        "con domicilio",
        "c.p.",
        "código postal",
        "cp",
        "vive en",
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
