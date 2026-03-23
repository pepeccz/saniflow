"""Shared test fixtures for the Saniflow test suite.

Provides:
- sample_pdf_bytes: A real PDF (via PyMuPDF) containing PII text.
- sample_image_bytes: A simple PNG image (via Pillow) for visual detector tests.
- test_client: FastAPI TestClient for API tests.
- pipeline: A SanitizationPipeline instance.

NOTE: On Python 3.14 the spaCy/pydantic v1 incompatibility prevents
importing presidio_analyzer. We install sys.modules mocks here so that
all test modules can safely import the pipeline and app code.
"""

from __future__ import annotations

import sys
from io import BytesIO
from unittest.mock import MagicMock

import fitz  # PyMuPDF
import pytest
from PIL import Image

# ---------------------------------------------------------------------------
# Mock presidio_analyzer / spaCy if they are broken in this environment
# ---------------------------------------------------------------------------

_PRESIDIO_AVAILABLE = True

try:
    import presidio_analyzer  # noqa: F401
except Exception:
    _PRESIDIO_AVAILABLE = False

    _MOCK_MODULES = [
        "presidio_analyzer",
        "presidio_analyzer.nlp_engine",
        "presidio_analyzer.nlp_engine.nlp_engine_provider",
        "presidio_analyzer.nlp_engine.NlpEngineProvider",
    ]
    for mod_name in _MOCK_MODULES:
        if mod_name not in sys.modules:
            sys.modules[mod_name] = MagicMock()

# Expose so tests can check without re-importing
PRESIDIO_AVAILABLE = _PRESIDIO_AVAILABLE

# ---------------------------------------------------------------------------
# PII text used in fixtures
# ---------------------------------------------------------------------------

PII_TEXT = (
    "Juan Garcia, DNI: 12345678Z, email: juan@example.com, "
    "tel: +34 612345678, IBAN: ES9121000418450200051332"
)


# ---------------------------------------------------------------------------
# PDF fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_pdf_bytes() -> bytes:
    """Create a minimal single-page PDF containing PII text via PyMuPDF."""
    doc = fitz.open()  # new empty PDF
    page = doc.new_page(width=595, height=842)  # A4-ish

    # Insert the PII text near the top-left of the page.
    text_point = fitz.Point(72, 72)
    page.insert_text(text_point, PII_TEXT, fontsize=12)

    pdf_bytes = doc.tobytes(deflate=True)
    doc.close()
    return pdf_bytes


# ---------------------------------------------------------------------------
# Image fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_image_bytes() -> bytes:
    """Create a simple 200x100 white PNG image."""
    img = Image.new("RGB", (200, 100), color=(255, 255, 255))
    buf = BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# ---------------------------------------------------------------------------
# FastAPI TestClient
# ---------------------------------------------------------------------------


@pytest.fixture()
def test_client():
    """Provide an httpx AsyncClient bound to the Saniflow app."""
    from httpx import ASGITransport, AsyncClient

    from app.main import app

    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


# ---------------------------------------------------------------------------
# Pipeline instance
# ---------------------------------------------------------------------------


@pytest.fixture()
def pipeline():
    """Return a fresh SanitizationPipeline instance."""
    from app.pipeline.orchestrator import SanitizationPipeline

    return SanitizationPipeline()
