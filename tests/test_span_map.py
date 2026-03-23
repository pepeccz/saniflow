"""Unit tests for SpanMap offset-to-coordinate resolution."""

from __future__ import annotations

import pytest

from app.models.extraction import SpanInfo, SpanMap


class TestSpanMapAppendAndResolve:
    """Basic append + resolve behaviour."""

    def test_single_span_resolve(self):
        sm = SpanMap()
        info = SpanInfo(text="Hello", bbox=(0.0, 0.0, 50.0, 12.0), page=0)
        sm.append(info)

        results = sm.resolve(0, 5)

        assert len(results) == 1
        assert results[0] == (0, (0.0, 0.0, 50.0, 12.0))

    def test_cursor_advances_after_append(self):
        sm = SpanMap()
        info = SpanInfo(text="abc", bbox=(0.0, 0.0, 30.0, 10.0), page=0)
        sm.append(info)

        assert sm.cursor == 3

    def test_advance_moves_cursor_without_span(self):
        sm = SpanMap()
        info = SpanInfo(text="Hi", bbox=(0.0, 0.0, 20.0, 10.0), page=0)
        sm.append(info)
        sm.advance(1)  # separator space

        assert sm.cursor == 3

    def test_len_counts_entries(self):
        sm = SpanMap()
        assert len(sm) == 0

        sm.append(SpanInfo(text="a", bbox=(0, 0, 10, 10), page=0))
        sm.append(SpanInfo(text="b", bbox=(10, 0, 20, 10), page=0))

        assert len(sm) == 2


class TestSpanMapMultiSpan:
    """PII spanning multiple spans should return all overlapping entries."""

    def test_multi_span_resolve(self):
        sm = SpanMap()
        # "Juan " at offset 0-4
        sm.append(SpanInfo(text="Juan", bbox=(0, 0, 40, 10), page=0))
        sm.advance(1)  # space
        # "Garcia" at offset 5-11
        sm.append(SpanInfo(text="Garcia", bbox=(45, 0, 100, 10), page=0))

        # A finding covering "Juan Garcia" → offsets 0..11
        results = sm.resolve(0, 11)

        assert len(results) == 2
        assert results[0][1] == (0, 0, 40, 10)
        assert results[1][1] == (45, 0, 100, 10)

    def test_partial_overlap_start(self):
        """Resolve range that starts inside a span."""
        sm = SpanMap()
        sm.append(SpanInfo(text="Hello", bbox=(0, 0, 50, 10), page=0))

        # Range [2, 5) → "llo" — still overlaps the single span
        results = sm.resolve(2, 5)
        assert len(results) == 1

    def test_partial_overlap_end(self):
        """Resolve range that ends inside the next span."""
        sm = SpanMap()
        sm.append(SpanInfo(text="AA", bbox=(0, 0, 20, 10), page=0))
        sm.advance(1)
        sm.append(SpanInfo(text="BB", bbox=(25, 0, 45, 10), page=0))

        # Range [1, 4) → overlaps both spans
        results = sm.resolve(1, 4)
        assert len(results) == 2


class TestSpanMapEmpty:
    """Edge case: empty SpanMap."""

    def test_resolve_empty_returns_empty(self):
        sm = SpanMap()
        assert sm.resolve(0, 10) == []

    def test_len_empty(self):
        sm = SpanMap()
        assert len(sm) == 0


class TestSpanMapOutOfBounds:
    """Offsets outside the valid range."""

    def test_resolve_beyond_end(self):
        sm = SpanMap()
        sm.append(SpanInfo(text="AB", bbox=(0, 0, 20, 10), page=0))

        # Completely past the span
        results = sm.resolve(100, 200)
        assert results == []

    def test_resolve_negative_start(self):
        sm = SpanMap()
        sm.append(SpanInfo(text="XY", bbox=(0, 0, 20, 10), page=0))

        # Negative start still resolves if it overlaps
        results = sm.resolve(-5, 1)
        assert len(results) == 1

    def test_resolve_zero_width_range(self):
        sm = SpanMap()
        sm.append(SpanInfo(text="AB", bbox=(0, 0, 20, 10), page=0))

        # [2, 2) → empty range, no overlap
        results = sm.resolve(2, 2)
        assert results == []


class TestSpanMapSingleCharacter:
    """Resolve works correctly for single-character spans."""

    def test_single_char_span(self):
        sm = SpanMap()
        sm.append(SpanInfo(text="X", bbox=(10, 20, 18, 32), page=1))

        results = sm.resolve(0, 1)
        assert len(results) == 1
        assert results[0] == (1, (10, 20, 18, 32))

    def test_single_char_not_matched_when_outside(self):
        sm = SpanMap()
        sm.append(SpanInfo(text="X", bbox=(10, 20, 18, 32), page=0))

        results = sm.resolve(1, 2)
        assert results == []
