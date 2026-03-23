"""Tests for JsonExtractor and JsonSanitizer (tasks 1.3 & 1.4).

Covers extraction (nested objects, arrays, empty JSON, root arrays,
deeply nested, non-string values) and sanitization (nested replace,
structure preserved, multiple findings, redaction styles).
"""

from __future__ import annotations

import json

import pytest

from app.models.extraction import SpanMap
from app.models.findings import EntityType, Finding, RedactionStyle
from app.pipeline.extractors.structured import JsonExtractor
from app.pipeline.sanitizers.structured import JsonSanitizer


# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture()
def extractor() -> JsonExtractor:
    return JsonExtractor()


@pytest.fixture()
def sanitizer() -> JsonSanitizer:
    return JsonSanitizer()


def _make_finding(
    original_text: str,
    entity_type: EntityType = EntityType.PERSON_NAME,
    score: float = 0.95,
) -> Finding:
    return Finding(
        entity_type=entity_type,
        original_text=original_text,
        score=score,
    )


# ═══════════════════════════════════════════════════════════════════════
# JsonExtractor tests
# ═══════════════════════════════════════════════════════════════════════


class TestJsonExtractorBasic:
    def test_flat_object(self, extractor: JsonExtractor) -> None:
        data = {"name": "Juan Garcia", "email": "juan@test.com"}
        raw = json.dumps(data).encode()

        result = extractor.extract(raw, "test.json")

        assert "name: Juan Garcia\n" in result.text
        assert "email: juan@test.com\n" in result.text
        assert isinstance(result.span_map, SpanMap)
        assert len(result.span_map) == 0
        assert result.pages == 1
        assert result.is_scanned is False

    def test_nested_object(self, extractor: JsonExtractor) -> None:
        data = {"user": {"name": "Juan", "email": "j@t.com"}}
        raw = json.dumps(data).encode()

        result = extractor.extract(raw, "test.json")

        assert "user.name: Juan\n" in result.text
        assert "user.email: j@t.com\n" in result.text

    def test_array_with_index(self, extractor: JsonExtractor) -> None:
        data = {"users": [{"name": "Juan"}, {"name": "Maria"}]}
        raw = json.dumps(data).encode()

        result = extractor.extract(raw, "test.json")

        assert "users.0.name: Juan\n" in result.text
        assert "users.1.name: Maria\n" in result.text

    def test_deeply_nested(self, extractor: JsonExtractor) -> None:
        data = {"a": {"b": {"c": {"d": "deep_value"}}}}
        raw = json.dumps(data).encode()

        result = extractor.extract(raw, "test.json")

        assert "a.b.c.d: deep_value\n" in result.text


class TestJsonExtractorEdgeCases:
    def test_empty_json_object(self, extractor: JsonExtractor) -> None:
        raw = b"{}"

        result = extractor.extract(raw, "empty.json")

        assert result.text == ""

    def test_empty_bytes(self, extractor: JsonExtractor) -> None:
        raw = b""

        result = extractor.extract(raw, "empty.json")

        assert result.text == ""

    def test_whitespace_only(self, extractor: JsonExtractor) -> None:
        raw = b"   "

        result = extractor.extract(raw, "empty.json")

        assert result.text == ""

    def test_root_array(self, extractor: JsonExtractor) -> None:
        data = [{"name": "Juan"}, {"name": "Maria"}]
        raw = json.dumps(data).encode()

        result = extractor.extract(raw, "test.json")

        assert "0.name: Juan\n" in result.text
        assert "1.name: Maria\n" in result.text

    def test_root_array_of_strings(self, extractor: JsonExtractor) -> None:
        data = ["Juan Garcia", "Maria Lopez"]
        raw = json.dumps(data).encode()

        result = extractor.extract(raw, "test.json")

        assert "0: Juan Garcia\n" in result.text
        assert "1: Maria Lopez\n" in result.text

    def test_skips_non_string_values(self, extractor: JsonExtractor) -> None:
        data = {
            "name": "Juan",
            "age": 30,
            "active": True,
            "score": 9.5,
            "address": None,
        }
        raw = json.dumps(data).encode()

        result = extractor.extract(raw, "test.json")

        assert "name: Juan\n" in result.text
        # Non-string values should NOT appear in the extracted text.
        assert "age" not in result.text
        assert "active" not in result.text
        assert "score" not in result.text
        assert "address" not in result.text

    def test_mixed_array(self, extractor: JsonExtractor) -> None:
        data = {"items": ["text_value", 42, True, None, "another"]}
        raw = json.dumps(data).encode()

        result = extractor.extract(raw, "test.json")

        assert "items.0: text_value\n" in result.text
        assert "items.4: another\n" in result.text
        # Non-string items skipped
        assert "42" not in result.text

    def test_empty_string_value(self, extractor: JsonExtractor) -> None:
        data = {"name": ""}
        raw = json.dumps(data).encode()

        result = extractor.extract(raw, "test.json")

        assert "name: \n" in result.text

    def test_utf8_with_replace(self, extractor: JsonExtractor) -> None:
        raw = b'{"name": "Caf\xc3\xa9 Nost\xc3\xa1lgico"}'

        result = extractor.extract(raw, "test.json")

        assert "name: Caf\u00e9 Nost\u00e1lgico\n" in result.text

    def test_empty_array(self, extractor: JsonExtractor) -> None:
        raw = b"[]"

        result = extractor.extract(raw, "test.json")

        assert result.text == ""


# ═══════════════════════════════════════════════════════════════════════
# JsonSanitizer tests
# ═══════════════════════════════════════════════════════════════════════


class TestJsonSanitizerBasic:
    def test_replace_flat_value(self, sanitizer: JsonSanitizer) -> None:
        data = {"name": "Juan Garcia", "city": "Madrid"}
        raw = json.dumps(data).encode()
        findings = [_make_finding("Juan Garcia")]

        result = sanitizer.sanitize(raw, findings, "test.json")
        output = json.loads(result)

        assert "Juan Garcia" not in output["name"]
        assert output["city"] == "Madrid"

    def test_replace_nested_value(self, sanitizer: JsonSanitizer) -> None:
        data = {"user": {"name": "Juan Garcia", "role": "admin"}}
        raw = json.dumps(data).encode()
        findings = [_make_finding("Juan Garcia")]

        result = sanitizer.sanitize(raw, findings, "test.json")
        output = json.loads(result)

        assert "Juan Garcia" not in output["user"]["name"]
        assert output["user"]["role"] == "admin"

    def test_replace_in_array(self, sanitizer: JsonSanitizer) -> None:
        data = {"users": [{"name": "Juan"}, {"name": "Maria"}]}
        raw = json.dumps(data).encode()
        findings = [_make_finding("Juan")]

        result = sanitizer.sanitize(raw, findings, "test.json")
        output = json.loads(result)

        assert "Juan" not in output["users"][0]["name"]
        assert output["users"][1]["name"] == "Maria"

    def test_multiple_findings(self, sanitizer: JsonSanitizer) -> None:
        data = {"name": "Juan Garcia", "email": "juan@test.com"}
        raw = json.dumps(data).encode()
        findings = [
            _make_finding("Juan Garcia", EntityType.PERSON_NAME),
            _make_finding("juan@test.com", EntityType.EMAIL),
        ]

        result = sanitizer.sanitize(raw, findings, "test.json")
        output = json.loads(result)

        assert "Juan Garcia" not in output["name"]
        assert "juan@test.com" not in output["email"]


class TestJsonSanitizerStructure:
    def test_preserves_json_structure(self, sanitizer: JsonSanitizer) -> None:
        data = {
            "users": [
                {"name": "Juan", "age": 30, "active": True},
                {"name": "Maria", "age": 25, "active": False},
            ],
            "meta": {"count": 2},
        }
        raw = json.dumps(data).encode()
        findings = [_make_finding("Juan"), _make_finding("Maria")]

        result = sanitizer.sanitize(raw, findings, "test.json")
        output = json.loads(result)

        # Structure preserved
        assert len(output["users"]) == 2
        assert output["users"][0]["age"] == 30
        assert output["users"][0]["active"] is True
        assert output["users"][1]["age"] == 25
        assert output["users"][1]["active"] is False
        assert output["meta"]["count"] == 2

    def test_output_is_valid_json(self, sanitizer: JsonSanitizer) -> None:
        data = {"name": "Juan Garcia"}
        raw = json.dumps(data).encode()
        findings = [_make_finding("Juan Garcia")]

        result = sanitizer.sanitize(raw, findings, "test.json")

        # Must not raise
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_output_is_indented(self, sanitizer: JsonSanitizer) -> None:
        data = {"name": "Juan Garcia"}
        raw = json.dumps(data).encode()
        findings = [_make_finding("Juan Garcia")]

        result = sanitizer.sanitize(raw, findings, "test.json")
        text = result.decode("utf-8")

        # json.dumps(indent=2) produces newlines and spaces
        assert "\n" in text
        assert "  " in text

    def test_empty_json_returns_original(self, sanitizer: JsonSanitizer) -> None:
        raw = b""

        result = sanitizer.sanitize(raw, [], "empty.json")

        assert result == b""


class TestJsonSanitizerRedactionStyles:
    def test_black_style_uses_block_chars(self, sanitizer: JsonSanitizer) -> None:
        data = {"name": "Juan"}
        raw = json.dumps(data).encode()
        findings = [_make_finding("Juan")]

        result = sanitizer.sanitize(
            raw, findings, "test.json", style=RedactionStyle.BLACK,
        )
        output = json.loads(result)

        assert output["name"] == "\u2588" * 4

    def test_placeholder_style_uses_entity_label(
        self, sanitizer: JsonSanitizer,
    ) -> None:
        data = {"name": "Juan"}
        raw = json.dumps(data).encode()
        findings = [_make_finding("Juan", EntityType.PERSON_NAME)]

        result = sanitizer.sanitize(
            raw, findings, "test.json", style=RedactionStyle.PLACEHOLDER,
        )
        output = json.loads(result)

        assert output["name"] == "[PERSON_NAME]"

    def test_blur_style_uses_entity_label(self, sanitizer: JsonSanitizer) -> None:
        data = {"email": "juan@test.com"}
        raw = json.dumps(data).encode()
        findings = [_make_finding("juan@test.com", EntityType.EMAIL)]

        result = sanitizer.sanitize(
            raw, findings, "test.json", style=RedactionStyle.BLUR,
        )
        output = json.loads(result)

        assert output["email"] == "[EMAIL]"

    def test_skips_finding_without_original_text(
        self, sanitizer: JsonSanitizer,
    ) -> None:
        data = {"name": "Juan"}
        raw = json.dumps(data).encode()
        finding = Finding(
            entity_type=EntityType.PERSON_NAME,
            original_text=None,
            score=0.95,
        )

        result = sanitizer.sanitize(raw, [finding], "test.json")
        output = json.loads(result)

        assert output["name"] == "Juan"

    def test_partial_string_replacement(self, sanitizer: JsonSanitizer) -> None:
        data = {"greeting": "Hello Juan Garcia, welcome!"}
        raw = json.dumps(data).encode()
        findings = [_make_finding("Juan Garcia")]

        result = sanitizer.sanitize(
            raw, findings, "test.json", style=RedactionStyle.PLACEHOLDER,
        )
        output = json.loads(result)

        assert output["greeting"] == "Hello [PERSON_NAME], welcome!"
