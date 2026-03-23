"""Unit tests for custom Spanish Presidio recognizers.

Tests the regex patterns used by EsPhoneRecognizer and EsAddressRecognizer.
Since presidio_analyzer may not be importable in all environments (e.g.,
Python 3.14 + pydantic v1 / spaCy incompatibility), we test the underlying
regex patterns directly using the ``re`` module.

When Presidio IS available, we also test through the recognizer API.
"""

from __future__ import annotations

import re

import numpy as np
import pytest
from PIL import Image

from app.models.findings import EntityType, Finding
from app.pipeline.detectors.recognizers.es_person import PERSON_DENY_LIST
from app.pipeline.detectors.text_pii import _ES_STOPWORDS, _filter_person_findings, _selective_title_case
from tests.conftest import PRESIDIO_AVAILABLE

# ---------------------------------------------------------------------------
# Regex patterns (duplicated from source for environments where the
# recognizer modules cannot be imported due to Presidio/spaCy issues)
# ---------------------------------------------------------------------------

# Phone patterns from app/pipeline/detectors/recognizers/es_phone.py
_PHONE_INTL = r"\+34[\s.\-]?[69]\d{2}[\s.\-]?\d{3}[\s.\-]?\d{3}"
_PHONE_LOCAL = r"\b[69]\d{2}[\s.\-]?\d{3}[\s.\-]?\d{3}\b"

# Address pattern from app/pipeline/detectors/recognizers/es_address.py
_STREET_TYPES = (
    r"(?:"
    r"[Cc](?:alle|/)"
    r"|[Cc]\."
    r"|[Aa]v(?:da)?\.?"
    r"|[Aa]venida"
    r"|[Pp]laza"
    r"|[Pp](?:za?)?\.?"
    r"|[Pp]aseo"
    r"|[Pp]\u00ba"
    r"|[Cc]amino"
    r"|[Rr]onda"
    r"|[Tt]raves\u00eda"
    r"|[Cc]arrera"
    r")"
)
_STREET_BODY = (
    r"\s+.{3,40}?"
    r",?\s*\d{1,4}"
    r"(?:\s*[-,]\s*\d{1,3}[\u00ba\u00aa]?\s*[A-Za-z]?)?"
    r"(?:\s*,?\s*\d{5})?"
    r"(?:\s*,?\s*[A-Z\u00c1\u00c9\u00cd\u00d3\u00da\u00d1]"
    r"[a-z\u00e1\u00e9\u00ed\u00f3\u00fa\u00f1]+)?"
)
_ADDRESS_PATTERN = _STREET_TYPES + _STREET_BODY


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _phone_has_match(text: str) -> bool:
    """Return True if *text* matches any Spanish phone regex."""
    if re.search(_PHONE_INTL, text):
        return True
    if re.search(_PHONE_LOCAL, text):
        return True
    return False


def _address_has_match(text: str) -> bool:
    """Return True if *text* matches the Spanish address regex."""
    return bool(re.search(_ADDRESS_PATTERN, text))


# ===========================================================================
# EsPhoneRecognizer
# ===========================================================================


class TestEsPhoneRecognizerValid:
    """Valid Spanish phone numbers should be detected."""

    @pytest.mark.parametrize(
        "phone",
        [
            "+34 612 345 678",
            "+34 612345678",
            "+34-612-345-678",
            "+34.612.345.678",
            "+34 912 345 678",
        ],
    )
    def test_international_format(self, phone: str):
        assert _phone_has_match(phone), f"Expected match for '{phone}'"

    @pytest.mark.parametrize(
        "phone",
        [
            "612345678",
            "612 345 678",
            "912345678",
        ],
    )
    def test_local_format(self, phone: str):
        assert _phone_has_match(phone), f"Expected match for '{phone}'"


class TestEsPhoneRecognizerInvalid:
    """Non-phone strings should NOT be detected."""

    @pytest.mark.parametrize(
        "text",
        [
            "12345",
            "+1 555 123 4567",
            "Hello world",
            "",
        ],
    )
    def test_no_match(self, text: str):
        assert not _phone_has_match(text), f"Unexpected match in '{text}'"


# ===========================================================================
# EsAddressRecognizer
# ===========================================================================


class TestEsAddressRecognizerValid:
    """Valid Spanish addresses should be detected."""

    @pytest.mark.parametrize(
        "address",
        [
            "Calle Mayor 15",
            "Av. de la Constitucion 3",
            "Plaza de Espana 1",
            "Avda. Diagonal 123",
            "Paseo de Gracia 55",
            "C/ Gran Via 42",
        ],
    )
    def test_valid_address(self, address: str):
        assert _address_has_match(address), f"Expected match for '{address}'"


class TestEsAddressRecognizerInvalid:
    """Non-address strings should NOT be detected."""

    @pytest.mark.parametrize(
        "text",
        [
            "Hola mundo",
            "12345678Z",
            "juan@example.com",
            "",
        ],
    )
    def test_no_match(self, text: str):
        assert not _address_has_match(text), f"Unexpected match in '{text}'"


# ===========================================================================
# EsPersonRecognizer — CONSECUTIVE pattern removed
# ===========================================================================


class TestEsPersonConsecutiveRemoved:
    """Verify ES_PERSON_CONSECUTIVE pattern is no longer registered."""

    @pytest.mark.skipif(not PRESIDIO_AVAILABLE, reason="presidio not available")
    def test_patterns_registered(self):
        from app.pipeline.detectors.recognizers.es_person import EsPersonRecognizer

        recognizer = EsPersonRecognizer(supported_language="es")
        pattern_names = [p.name for p in recognizer.patterns]
        assert pattern_names == ["ES_PERSON_INVERTED", "ES_PERSON_STRUCTURED"]


# ===========================================================================
# _selective_title_case
# ===========================================================================


class TestSelectiveTitleCase:
    """Tests for selective title-case preprocessing."""

    def test_all_caps_converted(self):
        assert _selective_title_case("CABEZA CRUZ, PEPE") == "Cabeza Cruz, Pepe"

    def test_mixed_case_unchanged(self):
        text = "Condiciones Generales del Seguro"
        assert _selective_title_case(text) == text

    def test_lowercase_unchanged(self):
        text = "esto es texto normal"
        assert _selective_title_case(text) == text

    def test_accented_all_caps(self):
        assert _selective_title_case("ÁNGEL GARCÍA") == "Ángel García"

    def test_length_invariant(self):
        inputs = [
            "CABEZA CRUZ, PEPE",
            "Condiciones Generales del Seguro",
            "ÁNGEL GARCÍA LÓPEZ",
            "todo minúsculas",
            "MIXTO y Normal TEXT",
        ]
        for text in inputs:
            result = _selective_title_case(text)
            assert len(result) == len(text), f"Length mismatch for {text!r}"

    def test_single_uppercase_letter_untouched(self):
        text = "A B C"
        assert _selective_title_case(text) == text


# ===========================================================================
# _filter_person_findings
# ===========================================================================


def _make_person_finding(text: str, score: float = 0.85) -> Finding:
    return Finding(entity_type=EntityType.PERSON_NAME, original_text=text, score=score)


def _make_other_finding(text: str) -> Finding:
    return Finding(entity_type=EntityType.IBAN, original_text=text, score=0.99)


class TestFilterPersonFindings:
    """Tests for post-detection PERSON_NAME filtering."""

    def test_single_word_rejected(self):
        findings = [_make_person_finding("Seguro")]
        result = _filter_person_findings(findings, PERSON_DENY_LIST)
        assert result == []

    def test_five_plus_tokens_rejected(self):
        findings = [_make_person_finding("Juan García López Martínez Fernández")]
        result = _filter_person_findings(findings, PERSON_DENY_LIST)
        assert result == []

    def test_all_deny_list_tokens_rejected(self):
        findings = [_make_person_finding("Condiciones Generales")]
        result = _filter_person_findings(findings, PERSON_DENY_LIST)
        assert result == []

    def test_valid_name_passes(self):
        findings = [_make_person_finding("García López, María")]
        result = _filter_person_findings(findings, PERSON_DENY_LIST)
        assert len(result) == 1
        assert result[0].original_text == "García López, María"

    def test_non_person_entities_untouched(self):
        findings = [_make_other_finding("ES9121000418450200051332")]
        result = _filter_person_findings(findings, PERSON_DENY_LIST)
        assert len(result) == 1

    def test_mixed_findings_filtered_correctly(self):
        findings = [
            _make_person_finding("Seguro"),  # single word → out
            _make_person_finding("García López"),  # valid → in
            _make_other_finding("ES91210004"),  # non-person → in
            _make_person_finding("Condiciones Generales"),  # deny list → out
        ]
        result = _filter_person_findings(findings, PERSON_DENY_LIST)
        assert len(result) == 2
        assert result[0].original_text == "García López"
        assert result[1].entity_type == EntityType.IBAN

    # -- Stopword filter tests --

    @pytest.mark.parametrize(
        "text",
        [
            "del Seguro, en cumplimiento",
            "Condiciones de Póliza",
            "Según el Reglamento",
            "Para la Cobertura",
        ],
    )
    def test_stopword_tokens_rejected(self, text: str):
        """Findings containing Spanish stopwords should be rejected."""
        findings = [_make_person_finding(text)]
        result = _filter_person_findings(findings, PERSON_DENY_LIST)
        assert result == [], f"Expected rejection for '{text}'"

    def test_real_name_no_stopwords_passes(self):
        """Real person names with no stopwords should pass."""
        findings = [_make_person_finding("Cabeza Cruz, Pepe")]
        result = _filter_person_findings(findings, PERSON_DENY_LIST)
        assert len(result) == 1
        assert result[0].original_text == "Cabeza Cruz, Pepe"

    # -- Any-token deny-list filter tests (false-positive reduction) --

    @pytest.mark.parametrize(
        "text",
        [
            "Erupciones Volcánicas, Huracanes",
            "Terceros Asegurados, Beneficiarios",
            "Recibo Contendrá, Además",
            "Cardenal Gardoqui, Bilbao",
            "Gastos Indemnizaciones, Primas",
            "Coberturas Exclusiones, Riesgos",
        ],
    )
    def test_any_deny_token_rejected(self, text: str):
        """Findings with ANY token in the deny list should be rejected."""
        findings = [_make_person_finding(text)]
        result = _filter_person_findings(findings, PERSON_DENY_LIST)
        assert result == [], f"Expected rejection for '{text}'"


# ===========================================================================
# ES_PERSON_INVERTED regex — case sensitivity & newline boundary
# ===========================================================================


# Regex duplicated from es_person.py for environments where Presidio is mocked
_PERSON_INVERTED = (
    r"\b[A-ZÁÉÍÓÚÑ][a-záéíóúñA-ZÁÉÍÓÚÑ]+"
    r"[^\S\n]+[A-ZÁÉÍÓÚÑ][a-záéíóúñA-ZÁÉÍÓÚÑ]+"
    r",[^\S\n]*[A-ZÁÉÍÓÚÑ][a-záéíóúñA-ZÁÉÍÓÚÑ]+"
    r"(?:[^\S\n]+[A-ZÁÉÍÓÚÑ][a-záéíóúñA-ZÁÉÍÓÚÑ]+)?\b"
)


class TestEsPersonInvertedRegex:
    """Tests for the ES_PERSON_INVERTED regex pattern directly."""

    @pytest.fixture()
    def pattern(self) -> re.Pattern[str]:
        return re.compile(_PERSON_INVERTED)

    def test_properly_capitalised_match(self, pattern: re.Pattern[str]):
        assert pattern.search("Cabeza Cruz, Pepe")

    def test_lowercase_no_match(self, pattern: re.Pattern[str]):
        """Without (?i), all-lowercase should NOT match."""
        assert pattern.search("cabeza cruz, pepe") is None

    def test_does_not_cross_newline(self, pattern: re.Pattern[str]):
        """Regex should not match across line boundaries."""
        text = "Cabeza Cruz, Pepe\nSurne"
        match = pattern.search(text)
        # Should match "Cabeza Cruz, Pepe" but NOT include "Surne"
        assert match is not None
        assert "\n" not in match.group()


# ===========================================================================
# ES_DATE_OF_BIRTH regex — space separator
# ===========================================================================

# Regex duplicated from es_dob.py
_DOB_PATTERN = r"\b\d{1,2}[/\-\.\s]\d{1,2}[/\-\.\s]\d{2,4}\b"


class TestEsDobSpaceSeparator:
    """Tests for DOB regex with space separator support."""

    @pytest.fixture()
    def pattern(self) -> re.Pattern[str]:
        return re.compile(_DOB_PATTERN)

    @pytest.mark.parametrize(
        "text",
        [
            "25 08 2005",
            "1 1 90",
            "25/08/2005",
            "25-08-2005",
            "25.08.2005",
        ],
    )
    def test_valid_dates_match(self, pattern: re.Pattern[str], text: str):
        assert pattern.search(text), f"Expected match for '{text}'"

    @pytest.mark.parametrize(
        "text",
        [
            "hello world",
            "123456",
            "",
        ],
    )
    def test_invalid_dates_no_match(self, pattern: re.Pattern[str], text: str):
        assert pattern.search(text) is None, f"Unexpected match in '{text}'"


# ===========================================================================
# ES_PERSON_STRUCTURED regex — label-value pattern from ID documents
# ===========================================================================

_PERSON_STRUCTURED = (
    r"(?:APELLIDOS?|PRIMER\s+APELLIDO)"
    r"[:\s]*\n\s*"
    r"([A-ZÁÉÍÓÚÑ][A-ZÁÉÍÓÚÑa-záéíóúñ\s]+)"
    r"\n\s*"
    r"NOMBRE[:\s]*\n\s*"
    r"([A-ZÁÉÍÓÚÑ][A-ZÁÉÍÓÚÑa-záéíóúñ\s]+)"
)


class TestEsPersonStructuredRegex:
    """Tests for the ES_PERSON_STRUCTURED regex pattern."""

    @pytest.fixture()
    def pattern(self) -> re.Pattern[str]:
        return re.compile(_PERSON_STRUCTURED)

    def test_standard_dni_format(self, pattern: re.Pattern[str]):
        text = "APELLIDOS\nCABEZA CRUZ\nNOMBRE\nPEPE"
        match = pattern.search(text)
        assert match is not None
        assert match.group(1).strip() == "CABEZA CRUZ"
        assert match.group(2).strip() == "PEPE"

    def test_apellido_singular(self, pattern: re.Pattern[str]):
        text = "APELLIDO\nGARCIA\nNOMBRE\nMARIA"
        match = pattern.search(text)
        assert match is not None

    def test_primer_apellido_variant(self, pattern: re.Pattern[str]):
        text = "PRIMER APELLIDO\nLOPEZ\nNOMBRE\nJUAN"
        match = pattern.search(text)
        assert match is not None

    def test_with_colon_labels(self, pattern: re.Pattern[str]):
        text = "APELLIDOS:\nCABEZA CRUZ\nNOMBRE:\nPEPE"
        match = pattern.search(text)
        assert match is not None

    def test_no_labels_no_match(self, pattern: re.Pattern[str]):
        text = "Juan Garcia Lopez"
        assert pattern.search(text) is None

    def test_only_apellidos_no_nombre_no_match(self, pattern: re.Pattern[str]):
        text = "APELLIDOS\nCABEZA CRUZ"
        assert pattern.search(text) is None


# ===========================================================================
# _enhance_for_ocr — image enhancement for OCR
# ===========================================================================


class TestEnhanceForOcr:
    """Tests for the OCR image enhancement function."""

    def test_output_is_grayscale(self):
        from app.pipeline.extractors.image import _enhance_for_ocr

        img = Image.new("RGB", (100, 80), color=(128, 128, 128))
        result = _enhance_for_ocr(img)
        assert result.mode in ("L", "P"), f"Expected grayscale, got {result.mode}"

    def test_dimensions_preserved(self):
        from app.pipeline.extractors.image import _enhance_for_ocr

        img = Image.new("RGB", (200, 150), color=(64, 64, 64))
        result = _enhance_for_ocr(img)
        assert result.size == (200, 150)

    def test_output_has_nonzero_pixels(self):
        from app.pipeline.extractors.image import _enhance_for_ocr

        img = Image.new("RGB", (100, 100), color=(100, 100, 100))
        result = _enhance_for_ocr(img)
        arr = np.array(result)
        assert arr.sum() > 0, "Enhanced image has all-zero pixels"


# ===========================================================================
# YuNet score threshold configuration
# ===========================================================================


class TestYunetScoreThreshold:
    """Tests for configurable YuNet face detection threshold."""

    def test_default_threshold_is_0_4(self):
        from app.config import Settings

        s = Settings()
        assert s.YUNET_SCORE_THRESHOLD == 0.4

    def test_threshold_overridable_via_env(self, monkeypatch: pytest.MonkeyPatch):
        from app.config import Settings

        monkeypatch.setenv("SANIFLOW_YUNET_SCORE_THRESHOLD", "0.5")
        s = Settings()
        assert s.YUNET_SCORE_THRESHOLD == 0.5
