"""Unit tests for the GLiNER PII detection layer.

Tests cover:
- GLINER_LABEL_MAP completeness
- _is_duplicate logic (exact, substring, no overlap)
- merge_findings deduplication behaviour
- GlinerPiiDetector graceful degradation when gliner is not installed
- Config defaults (GLINER_ENABLED=False)

NOTE: These tests do NOT require the ``gliner`` package or the actual
transformer model.  All model interactions are mocked.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from app.config import Settings
from app.models.findings import EntityType, Finding
from app.pipeline.detectors.gliner_pii import (
    GLINER_LABEL_MAP,
    GlinerPiiDetector,
    _is_duplicate,
    merge_findings,
)


# ── GLINER_LABEL_MAP tests ───────────────────────────────────────────


class TestGlinerLabelMap:
    """Verify the label map covers all expected GLiNER labels."""

    EXPECTED_LABELS = {
        "person", "email", "phone number", "iban", "credit card number",
        "date of birth", "address", "passport number", "social security number",
        "driver license", "medical condition", "medication", "ip address",
        "bank account", "tax identification number", "vehicle registration",
    }

    def test_all_expected_labels_are_mapped(self):
        assert self.EXPECTED_LABELS == set(GLINER_LABEL_MAP.keys())

    def test_person_maps_to_person_name(self):
        assert GLINER_LABEL_MAP["person"] == EntityType.PERSON_NAME

    def test_email_maps_to_email(self):
        assert GLINER_LABEL_MAP["email"] == EntityType.EMAIL

    def test_phone_maps_to_phone(self):
        assert GLINER_LABEL_MAP["phone number"] == EntityType.PHONE

    def test_iban_maps_to_iban(self):
        assert GLINER_LABEL_MAP["iban"] == EntityType.IBAN

    def test_dob_maps_to_date_of_birth(self):
        assert GLINER_LABEL_MAP["date of birth"] == EntityType.DATE_OF_BIRTH

    def test_address_maps_to_address(self):
        assert GLINER_LABEL_MAP["address"] == EntityType.ADDRESS

    def test_passport_maps_to_dni_nie(self):
        assert GLINER_LABEL_MAP["passport number"] == EntityType.DNI_NIE

    def test_ssn_maps_to_dni_nie(self):
        assert GLINER_LABEL_MAP["social security number"] == EntityType.DNI_NIE

    def test_credit_card_maps_to_sensitive_data(self):
        assert GLINER_LABEL_MAP["credit card number"] == EntityType.SENSITIVE_DATA

    def test_unknown_label_falls_back_to_sensitive_data(self):
        """Unmapped labels should default to SENSITIVE_DATA via .get()."""
        result = GLINER_LABEL_MAP.get("unknown_label", EntityType.SENSITIVE_DATA)
        assert result == EntityType.SENSITIVE_DATA


# ── _is_duplicate tests ──────────────────────────────────────────────


class TestIsDuplicate:
    """Test the _is_duplicate helper for various overlap scenarios."""

    def test_exact_match(self):
        a = Finding(entity_type=EntityType.PERSON_NAME, original_text="Juan Garcia", score=0.9)
        b = Finding(entity_type=EntityType.PERSON_NAME, original_text="Juan Garcia", score=0.8)
        assert _is_duplicate(a, b) is True

    def test_case_insensitive_match(self):
        a = Finding(entity_type=EntityType.PERSON_NAME, original_text="JUAN GARCIA", score=0.9)
        b = Finding(entity_type=EntityType.PERSON_NAME, original_text="juan garcia", score=0.8)
        assert _is_duplicate(a, b) is True

    def test_substring_match(self):
        a = Finding(entity_type=EntityType.PERSON_NAME, original_text="Juan", score=0.9)
        b = Finding(entity_type=EntityType.PERSON_NAME, original_text="Juan Garcia", score=0.8)
        assert _is_duplicate(a, b) is True

    def test_no_overlap(self):
        a = Finding(entity_type=EntityType.PERSON_NAME, original_text="Juan Garcia", score=0.9)
        b = Finding(entity_type=EntityType.EMAIL, original_text="juan@example.com", score=0.8)
        assert _is_duplicate(a, b) is False

    def test_none_original_text(self):
        a = Finding(entity_type=EntityType.PERSON_NAME, original_text=None, score=0.9)
        b = Finding(entity_type=EntityType.PERSON_NAME, original_text="Juan", score=0.8)
        assert _is_duplicate(a, b) is False

    def test_both_none_original_text(self):
        a = Finding(entity_type=EntityType.PERSON_NAME, original_text=None, score=0.9)
        b = Finding(entity_type=EntityType.PERSON_NAME, original_text=None, score=0.8)
        assert _is_duplicate(a, b) is False

    def test_empty_string(self):
        a = Finding(entity_type=EntityType.PERSON_NAME, original_text="", score=0.9)
        b = Finding(entity_type=EntityType.PERSON_NAME, original_text="", score=0.8)
        assert _is_duplicate(a, b) is False


# ── merge_findings tests ─────────────────────────────────────────────


class TestMergeFindings:
    """Test finding deduplication and merging logic."""

    def test_no_overlap_appends_both(self):
        existing = [
            Finding(entity_type=EntityType.PERSON_NAME, original_text="Juan Garcia", score=0.9),
        ]
        new = [
            Finding(entity_type=EntityType.EMAIL, original_text="juan@example.com", score=0.95),
        ]
        result = merge_findings(existing, new)
        assert len(result) == 2

    def test_duplicate_keeps_higher_score(self):
        existing = [
            Finding(entity_type=EntityType.PERSON_NAME, original_text="Juan Garcia", score=0.7),
        ]
        new = [
            Finding(entity_type=EntityType.PERSON_NAME, original_text="Juan Garcia", score=0.92),
        ]
        result = merge_findings(existing, new)
        assert len(result) == 1
        assert result[0].score == 0.92

    def test_duplicate_keeps_existing_when_higher(self):
        existing = [
            Finding(entity_type=EntityType.PERSON_NAME, original_text="Juan Garcia", score=0.95),
        ]
        new = [
            Finding(entity_type=EntityType.PERSON_NAME, original_text="Juan Garcia", score=0.7),
        ]
        result = merge_findings(existing, new)
        assert len(result) == 1
        assert result[0].score == 0.95

    def test_empty_existing(self):
        result = merge_findings([], [
            Finding(entity_type=EntityType.IBAN, original_text="ES91...", score=0.99),
        ])
        assert len(result) == 1

    def test_empty_new(self):
        existing = [
            Finding(entity_type=EntityType.IBAN, original_text="ES91...", score=0.99),
        ]
        result = merge_findings(existing, [])
        assert len(result) == 1

    def test_none_original_text_always_appended(self):
        existing = [
            Finding(entity_type=EntityType.PERSON_NAME, original_text="Juan", score=0.9),
        ]
        new = [
            Finding(entity_type=EntityType.SENSITIVE_DATA, original_text=None, score=0.5),
        ]
        result = merge_findings(existing, new)
        assert len(result) == 2

    def test_does_not_mutate_input(self):
        existing = [
            Finding(entity_type=EntityType.PERSON_NAME, original_text="Juan Garcia", score=0.7),
        ]
        new = [
            Finding(entity_type=EntityType.PERSON_NAME, original_text="Juan Garcia", score=0.92),
        ]
        merge_findings(existing, new)
        assert existing[0].score == 0.7  # original list unchanged


# ── GlinerPiiDetector tests ──────────────────────────────────────────


class TestGlinerPiiDetector:
    """Test detector behaviour without requiring actual gliner package."""

    def setup_method(self):
        """Reset the class-level model cache before each test."""
        GlinerPiiDetector._model = None

    def test_graceful_degradation_import_error(self):
        """When gliner is not installed, detect() returns empty list."""
        with patch.dict("sys.modules", {"gliner": None}):
            # Force reload path by resetting model
            GlinerPiiDetector._model = None
            detector = GlinerPiiDetector()
            result = detector.detect("Juan Garcia lives at Calle Mayor 5")
            assert result == []

    def test_detect_maps_entities_correctly(self):
        """With a mocked model, verify entity mapping works."""
        mock_model = MagicMock()
        mock_model.predict_entities.return_value = [
            {"text": "Juan Garcia", "label": "person", "score": 0.95},
            {"text": "ES9121000418450200051332", "label": "iban", "score": 0.99},
            {"text": "192.168.1.1", "label": "ip address", "score": 0.88},
        ]
        GlinerPiiDetector._model = mock_model

        detector = GlinerPiiDetector()
        findings = detector.detect("test text")

        assert len(findings) == 3
        assert findings[0].entity_type == EntityType.PERSON_NAME
        assert findings[0].original_text == "Juan Garcia"
        assert findings[0].score == 0.95

        assert findings[1].entity_type == EntityType.IBAN
        assert findings[1].score == 0.99

        assert findings[2].entity_type == EntityType.SENSITIVE_DATA
        assert findings[2].original_text == "192.168.1.1"

    def test_detect_unknown_label_maps_to_sensitive_data(self):
        """Unknown GLiNER labels should fall back to SENSITIVE_DATA."""
        mock_model = MagicMock()
        mock_model.predict_entities.return_value = [
            {"text": "ABC-123", "label": "totally_new_type", "score": 0.7},
        ]
        GlinerPiiDetector._model = mock_model

        detector = GlinerPiiDetector()
        findings = detector.detect("test text")

        assert len(findings) == 1
        assert findings[0].entity_type == EntityType.SENSITIVE_DATA

    def test_detect_handles_prediction_exception(self):
        """If predict_entities raises, return empty list."""
        mock_model = MagicMock()
        mock_model.predict_entities.side_effect = RuntimeError("boom")
        GlinerPiiDetector._model = mock_model

        detector = GlinerPiiDetector()
        result = detector.detect("test text")
        assert result == []

    def test_scores_are_rounded(self):
        """Scores from GLiNER should be rounded to 2 decimal places."""
        mock_model = MagicMock()
        mock_model.predict_entities.return_value = [
            {"text": "test", "label": "person", "score": 0.956789},
        ]
        GlinerPiiDetector._model = mock_model

        detector = GlinerPiiDetector()
        findings = detector.detect("test text")
        assert findings[0].score == 0.96


# ── Config defaults test ─────────────────────────────────────────────


class TestGlinerConfig:
    """Verify GLiNER config defaults."""

    def test_gliner_disabled_by_default(self):
        s = Settings()
        assert s.GLINER_ENABLED is False

    def test_gliner_threshold_default(self):
        s = Settings()
        assert s.GLINER_THRESHOLD == 0.5

    def test_gliner_model_default(self):
        s = Settings()
        assert s.GLINER_MODEL == "urchade/gliner_multi_pii-v1"

    def test_gliner_labels_is_list(self):
        s = Settings()
        assert isinstance(s.GLINER_LABELS, list)
        assert len(s.GLINER_LABELS) > 0
