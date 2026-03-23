"""Tests for HtmlExtractor and HtmlSanitizer (tasks 3.2 & 3.3).

Covers extraction (basic HTML, scripts/styles stripped, nested tags,
empty HTML) and sanitization (text replaced in tags, structure preserved,
all redaction styles, no findings passthrough, import guard).
"""

from __future__ import annotations

import pytest

from app.models.extraction import SpanMap
from app.models.findings import EntityType, Finding, RedactionStyle
from app.pipeline.extractors.structured import HtmlExtractor
from app.pipeline.sanitizers.structured import HtmlSanitizer


# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture()
def extractor() -> HtmlExtractor:
    return HtmlExtractor()


@pytest.fixture()
def sanitizer() -> HtmlSanitizer:
    return HtmlSanitizer()


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
# HtmlExtractor tests
# ═══════════════════════════════════════════════════════════════════════


class TestHtmlExtractorBasic:
    def test_basic_html(self, extractor: HtmlExtractor) -> None:
        html = b"<html><body><p>Juan Garcia</p></body></html>"

        result = extractor.extract(html, "test.html")

        assert "Juan Garcia" in result.text
        assert isinstance(result.span_map, SpanMap)
        assert len(result.span_map) == 0
        assert result.pages == 1
        assert result.is_scanned is False

    def test_scripts_stripped(self, extractor: HtmlExtractor) -> None:
        html = (
            b"<html><body>"
            b"<script>var secret = 'password';</script>"
            b"<p>Visible text</p>"
            b"</body></html>"
        )

        result = extractor.extract(html, "test.html")

        assert "Visible text" in result.text
        assert "secret" not in result.text
        assert "password" not in result.text

    def test_styles_stripped(self, extractor: HtmlExtractor) -> None:
        html = (
            b"<html><head><style>body { color: red; }</style></head>"
            b"<body><p>Styled text</p></body></html>"
        )

        result = extractor.extract(html, "test.html")

        assert "Styled text" in result.text
        assert "color" not in result.text

    def test_nested_tags(self, extractor: HtmlExtractor) -> None:
        html = (
            b"<div><ul><li><strong>Juan</strong></li>"
            b"<li><em>Maria</em></li></ul></div>"
        )

        result = extractor.extract(html, "test.html")

        assert "Juan" in result.text
        assert "Maria" in result.text

    def test_empty_html(self, extractor: HtmlExtractor) -> None:
        result = extractor.extract(b"", "empty.html")

        assert result.text == ""
        assert result.pages == 1
        assert result.is_scanned is False

    def test_whitespace_only(self, extractor: HtmlExtractor) -> None:
        result = extractor.extract(b"   ", "empty.html")

        assert result.text == ""

    def test_utf8_with_replace(self, extractor: HtmlExtractor) -> None:
        html = b"<p>Caf\xc3\xa9 Nost\xc3\xa1lgico</p>"

        result = extractor.extract(html, "test.html")

        assert "Caf\u00e9 Nost\u00e1lgico" in result.text

    def test_multiple_paragraphs_separated(
        self, extractor: HtmlExtractor,
    ) -> None:
        html = b"<p>First paragraph</p><p>Second paragraph</p>"

        result = extractor.extract(html, "test.html")

        assert "First paragraph" in result.text
        assert "Second paragraph" in result.text


# ═══════════════════════════════════════════════════════════════════════
# HtmlSanitizer tests
# ═══════════════════════════════════════════════════════════════════════


class TestHtmlSanitizerBasic:
    def test_replace_text_in_tag(self, sanitizer: HtmlSanitizer) -> None:
        html = b"<p>Juan Garcia lives here</p>"
        findings = [_make_finding("Juan Garcia")]

        result = sanitizer.sanitize(html, findings, "test.html")
        text = result.decode("utf-8")

        assert "Juan Garcia" not in text
        assert "<p>" in text
        assert "</p>" in text

    def test_structure_preserved(self, sanitizer: HtmlSanitizer) -> None:
        html = (
            b"<div><h1>Title</h1>"
            b"<p>Juan Garcia</p>"
            b"<span>Other text</span></div>"
        )
        findings = [_make_finding("Juan Garcia")]

        result = sanitizer.sanitize(html, findings, "test.html")
        text = result.decode("utf-8")

        assert "<div>" in text
        assert "<h1>Title</h1>" in text
        assert "<span>Other text</span>" in text
        assert "Juan Garcia" not in text

    def test_multiple_findings(self, sanitizer: HtmlSanitizer) -> None:
        html = (
            b"<p>Juan Garcia</p>"
            b"<p>juan@test.com</p>"
        )
        findings = [
            _make_finding("Juan Garcia", EntityType.PERSON_NAME),
            _make_finding("juan@test.com", EntityType.EMAIL),
        ]

        result = sanitizer.sanitize(html, findings, "test.html")
        text = result.decode("utf-8")

        assert "Juan Garcia" not in text
        assert "juan@test.com" not in text

    def test_no_findings_passthrough(self, sanitizer: HtmlSanitizer) -> None:
        html = b"<p>Hello world</p>"

        result = sanitizer.sanitize(html, [], "test.html")

        assert result == b"<p>Hello world</p>"

    def test_empty_html_returns_original(
        self, sanitizer: HtmlSanitizer,
    ) -> None:
        result = sanitizer.sanitize(b"", [], "empty.html")

        assert result == b""


class TestHtmlSanitizerRedactionStyles:
    def test_black_style_uses_block_chars(
        self, sanitizer: HtmlSanitizer,
    ) -> None:
        html = b"<p>Juan</p>"
        findings = [_make_finding("Juan")]

        result = sanitizer.sanitize(
            html, findings, "test.html", style=RedactionStyle.BLACK,
        )
        text = result.decode("utf-8")

        assert "\u2588" * 4 in text

    def test_placeholder_style_uses_entity_label(
        self, sanitizer: HtmlSanitizer,
    ) -> None:
        html = b"<p>Juan</p>"
        findings = [_make_finding("Juan", EntityType.PERSON_NAME)]

        result = sanitizer.sanitize(
            html, findings, "test.html", style=RedactionStyle.PLACEHOLDER,
        )
        text = result.decode("utf-8")

        assert "[PERSON_NAME]" in text

    def test_blur_style_uses_entity_label(
        self, sanitizer: HtmlSanitizer,
    ) -> None:
        html = b"<p>juan@test.com</p>"
        findings = [_make_finding("juan@test.com", EntityType.EMAIL)]

        result = sanitizer.sanitize(
            html, findings, "test.html", style=RedactionStyle.BLUR,
        )
        text = result.decode("utf-8")

        assert "[EMAIL]" in text

    def test_skips_finding_without_original_text(
        self, sanitizer: HtmlSanitizer,
    ) -> None:
        html = b"<p>Juan</p>"
        finding = Finding(
            entity_type=EntityType.PERSON_NAME,
            original_text=None,
            score=0.95,
        )

        result = sanitizer.sanitize(html, [finding], "test.html")
        text = result.decode("utf-8")

        assert "Juan" in text

    def test_partial_text_replacement(
        self, sanitizer: HtmlSanitizer,
    ) -> None:
        html = b"<p>Hello Juan Garcia, welcome!</p>"
        findings = [_make_finding("Juan Garcia")]

        result = sanitizer.sanitize(
            html, findings, "test.html", style=RedactionStyle.PLACEHOLDER,
        )
        text = result.decode("utf-8")

        assert "Hello [PERSON_NAME], welcome!" in text


# ═══════════════════════════════════════════════════════════════════════
# Import guard tests
# ═══════════════════════════════════════════════════════════════════════


class TestImportGuard:
    def test_extractor_raises_without_bs4(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import app.pipeline.extractors.structured as ext_mod

        def _broken_require() -> None:
            msg = (
                "beautifulsoup4 is required for HTML support. "
                "Install it with: pip install 'saniflow[structured]'"
            )
            raise RuntimeError(msg)

        monkeypatch.setattr(ext_mod, "_require_bs4", _broken_require)
        extractor = HtmlExtractor()

        with pytest.raises(RuntimeError, match="beautifulsoup4 is required"):
            extractor.extract(b"<p>text</p>", "test.html")

    def test_sanitizer_raises_without_bs4(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import app.pipeline.sanitizers.structured as san_mod

        def _broken_require() -> None:
            msg = (
                "beautifulsoup4 is required for HTML support. "
                "Install it with: pip install 'saniflow[structured]'"
            )
            raise RuntimeError(msg)

        monkeypatch.setattr(san_mod, "_require_bs4", _broken_require)
        sanitizer = HtmlSanitizer()

        with pytest.raises(RuntimeError, match="beautifulsoup4 is required"):
            sanitizer.sanitize(b"<p>text</p>", [], "test.html")
