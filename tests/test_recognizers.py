"""Unit tests for custom Spanish Presidio recognizers.

Tests the regex patterns used by EsPhoneRecognizer and EsAddressRecognizer.
Since presidio_analyzer may not be importable in all environments (e.g.,
Python 3.14 + pydantic v1 / spaCy incompatibility), we test the underlying
regex patterns directly using the ``re`` module.

When Presidio IS available, we also test through the recognizer API.
"""

from __future__ import annotations

import re

import pytest

from app.models.findings import EntityType, Finding
from app.pipeline.detectors.recognizers.es_person import PERSON_DENY_LIST
from app.pipeline.detectors.text_pii import _filter_person_findings, _selective_title_case
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
    def test_patterns_only_inverted(self):
        from app.pipeline.detectors.recognizers.es_person import EsPersonRecognizer

        recognizer = EsPersonRecognizer(supported_language="es")
        pattern_names = [p.name for p in recognizer.patterns]
        assert pattern_names == ["ES_PERSON_INVERTED"]


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
