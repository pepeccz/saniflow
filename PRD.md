# PRD: Saniflow

> **The open-source sanitization layer between your documents and AI.**

**Version**: 0.1.0-draft
**Author**: Gentleman Programming
**Date**: 2026-03-23
**Status**: Draft

---

## 1. Problem Statement

The AI revolution has a blind spot: **data leakage**.

Every day, companies feed documents into AI models — contracts, invoices, medical records, identity documents — without removing the personally identifiable information (PII) they contain. The document goes into a language model, and suddenly a person's DNI, home address, bank account number, and face are sitting in a third-party system with no guarantees about retention or access.

**The risks are concrete:**

- **Legal**: GDPR fines up to 4% of global annual turnover or EUR 20M (whichever is higher). Spain's AEPD has issued fines exceeding EUR 1M for PII mishandling.
- **Financial**: Average cost of a data breach in 2025: USD 4.88M (IBM Cost of a Data Breach Report). Document-sourced leaks are among the hardest to trace and remediate.
- **Reputational**: A single leaked client document can destroy years of trust. Law firms, healthcare providers, and financial institutions face existential risk.
- **Compliance**: SOC 2, HIPAA, and ISO 27001 audits increasingly ask: "How do you sanitize documents before sending them to AI providers?"

**Current solutions fail in different ways:**

| Approach | Problem |
|----------|---------|
| Manual redaction (Adobe, etc.) | Slow, expensive, error-prone, does not scale |
| Visual overlays (black rectangles) | **Fake security** — underlying text is still extractable from the PDF |
| Cloud-based DLP (AWS Comprehend, Google DLP) | Sends your PII to yet another cloud service to detect PII. Ironic. |
| Microsoft Presidio (library) | Detection only — no API, no document handling, no redaction pipeline |
| "Don't send documents to AI" | Unrealistic. The productivity gains are too significant. |

Saniflow exists because **the problem is not AI — the problem is sending unsanitized documents to AI.**

---

## 2. Vision

Saniflow becomes the **standard sanitization layer** between documents and any external system — AI models, third-party APIs, cloud storage, or human recipients.

### Before Saniflow

```
Company → uploads contract.pdf → ChatGPT / Claude / Gemini
          (contains: client name, DNI, address, IBAN, face photo)
          Result: PII is now in a third-party system. Compliance violation.
```

### After Saniflow

```
Company → uploads contract.pdf → Saniflow API → sanitized_contract.pdf → AI model
          (PII detected and permanently removed)
          Result: AI processes the document. No PII leaves the perimeter.
```

### The MCP Server Vision

Saniflow's ultimate form is an **MCP (Model Context Protocol) server** that AI tools consume natively. Instead of humans remembering to sanitize before uploading, the AI tool's pipeline automatically routes documents through Saniflow:

```
AI Tool → needs to read document → MCP call to Saniflow → receives sanitized content → processes safely
```

This makes sanitization invisible, automatic, and impossible to bypass.

---

## 3. Target Users

### Primary: Companies Using AI with Document Workflows

- Legal firms processing contracts through AI for review or summarization
- Healthcare organizations digitizing patient records
- Financial institutions running compliance checks via AI
- HR departments processing CVs and employee documents
- Any company with a "send to AI" button in their workflow

### Secondary: Developers Building AI Pipelines

- Engineers building RAG (Retrieval-Augmented Generation) systems that ingest documents
- Teams building AI agents that need to read files from company repositories
- MLOps engineers preprocessing training data to remove PII
- Compliance-focused developers who need a sanitization step in their CI/CD

### Tertiary: Individual Professionals

- Freelancers handling client documents who need to share sanitized versions
- Consultants who process third-party documents and need to strip identifying information
- Researchers working with sensitive datasets

---

## 4. Supported Document Types

### Current MVP

| R-ID | Type | Formats | Detection | Redaction | Priority |
|------|------|---------|-----------|-----------|----------|
| R-FMT-01 | PDF | `.pdf` (native text) | Text PII via Presidio + SpanMap coordinate resolution | Real redaction via PyMuPDF `add_redact_annot` + `apply_redactions` | P0 |
| R-FMT-02 | PDF (scanned) | `.pdf` (image-based pages) | OCR via `get_textpage_ocr(language="spa")` then Presidio | Same as native PDF | P0 |
| R-FMT-03 | Images | `.jpg`, `.jpeg`, `.png` | OCR via pytesseract `image_to_data` for text; OpenCV for faces | Black rectangle fill via Pillow/OpenCV | P0 |

### Future Formats

| R-ID | Type | Formats | Priority | Notes |
|------|------|---------|----------|-------|
| R-FMT-04 | Word | `.docx` | P1 | python-docx extraction, XML-level redaction |
| R-FMT-05 | Excel | `.xlsx` | P1 | Cell-level PII detection and replacement |
| R-FMT-06 | Plain text | `.txt`, `.csv` | P1 | Direct text processing, simplest pipeline |
| R-FMT-07 | Email | `.eml`, `.msg` | P2 | Header + body + attachment sanitization |
| R-FMT-08 | Presentations | `.pptx` | P2 | Slide text + embedded images |
| R-FMT-09 | HTML | `.html` | P3 | DOM-aware redaction |

---

## 5. PII Detection Capabilities

### 5.1 Text-Based PII Detection

All text PII detection is powered by **Presidio Analyzer** with a **spaCy `es_core_news_md`** NLP backend, configured for Spanish language processing.

| R-ID | Entity Type | Presidio Recognizer | Detection Method | Confidence | Example | Level |
|------|-------------|---------------------|------------------|------------|---------|-------|
| R-DET-01 | `PERSON_NAME` | `SpacyRecognizer` | spaCy NER (`es_core_news_md`) | 0.5 - 0.85 | "Juan Garcia Lopez" | standard |
| R-DET-02 | `DNI_NIE` (DNI) | `EsNifRecognizer` (built-in) | Regex + checksum validation | 0.9+ | "12345678Z" | standard |
| R-DET-03 | `DNI_NIE` (NIE) | `EsNieRecognizer` (built-in) | Regex + checksum validation | 0.9+ | "X1234567L" | standard |
| R-DET-04 | `EMAIL` | `EmailRecognizer` (built-in) | Regex pattern | 0.9+ | "juan@example.com" | standard |
| R-DET-05 | `PHONE` | `EsPhoneRecognizer` (custom) | Regex: `+34 6XX/9XX XXX XXX` variants | 0.7+ | "+34 612 345 678" | standard |
| R-DET-06 | `IBAN` | `IbanRecognizer` (built-in) | Regex + checksum validation | 0.9+ | "ES91 2100 0418 4502 0005 1332" | standard |
| R-DET-07 | `ADDRESS` | `EsAddressRecognizer` (custom) | Regex for Spanish patterns + context words | 0.4 - 0.6 | "Calle Mayor 15, 28001 Madrid" | strict |

**Custom recognizer details:**

- **`EsPhoneRecognizer`**: Handles international format (`+34 6XX XXX XXX`), local format (`612345678`), and common separators (spaces, dots, hyphens). Context words: "telefono", "movil", "llamar", "contacto", "tel".
- **`EsAddressRecognizer`**: Matches patterns starting with street type prefixes (`Calle`, `C/`, `Av.`, `Avda.`, `Plaza`, `Pza.`, `Paseo`) followed by street name, number, and optional postal code. Context words: "direccion", "domicilio", "residencia", "vive en". Low confidence due to high variability in Spanish address formats.

### 5.2 Visual PII Detection

Visual detection runs only in **strict** mode.

| R-ID | Entity Type | Technology | Model | Confidence Threshold | Description |
|------|-------------|------------|-------|---------------------|-------------|
| R-DET-08 | `FACE` | OpenCV `FaceDetectorYN` | YuNet (`face_detection_yunet_2023mar.onnx`, 340KB) | 0.9 | Detects frontal and angled faces, partial occlusion. Returns bbox + 5 landmarks. ~5ms per 320x320 frame. |
| R-DET-09 | `SIGNATURE` | OpenCV connected component analysis | Heuristic (no model) | N/A | **Experimental.** Grayscale → threshold → invert → filter by component size and aspect ratio. Moderate accuracy (~70-80%), false positives with stamps and handwritten notes. |

### 5.3 Detection Accuracy Expectations

| Entity Type | Expected Recall | Expected Precision | Confidence | Notes |
|-------------|----------------|-------------------|------------|-------|
| `DNI_NIE` | > 95% | > 99% | HIGH | Checksum validation makes this very reliable |
| `EMAIL` | > 95% | > 99% | HIGH | Pattern-based, well-defined format |
| `IBAN` | > 95% | > 99% | HIGH | Checksum validation |
| `PHONE` | > 85% | > 90% | HIGH | Custom regex covers common Spanish formats |
| `PERSON_NAME` | ~70-80% | ~75% | MEDIUM | spaCy `es_core_news_md` is decent but not perfect for all Spanish names |
| `ADDRESS` | ~50-60% | ~60% | LOW | Addresses are highly variable; regex cannot cover all patterns |
| `FACE` | > 85% | > 90% | HIGH | YuNet is mature and well-tested |
| `SIGNATURE` | ~60-70% | ~50-60% | LOW | Heuristic approach; experimental |

---

## 6. Sanitization Levels

### 6.1 Standard Level (R-LVL-01)

**Default.** Detects and redacts text-based PII only.

**What it covers:** PERSON_NAME, DNI_NIE, EMAIL, PHONE, IBAN

**What it does NOT cover:** ADDRESS (too many false positives at this level), FACE, SIGNATURE

**Use cases:**
- Routine document processing where visual content is not sensitive
- High-throughput pipelines where false positives must be minimized
- Documents without photographs or handwritten content

### 6.2 Strict Level (R-LVL-02)

**Everything in standard, plus visual PII and address detection.**

**Additional coverage:** ADDRESS, FACE, SIGNATURE

**Use cases:**
- Identity documents (DNI scans, passports) with photographs
- Contracts with signatures
- Any document where visual identification is a concern
- Maximum compliance scenarios

### 6.3 Future Levels

| Level | Description | Priority |
|-------|-------------|----------|
| **Custom** | Configurable per-entity rules: choose which entity types to detect, set custom confidence thresholds | P2 |
| **GDPR** | Preset that detects all GDPR-relevant personal data categories | P3 |
| **HIPAA** | Preset for the 18 HIPAA Safe Harbor identifiers | P3 |
| **Enterprise** | Company-defined policies: custom entity types, whitelists, mandatory redaction zones | P4 |

---

## 7. API Design

### 7.1 Current API (MVP)

Base URL: `http://localhost:8000`

#### `POST /api/v1/sanitize`

Sanitize a document by detecting and redacting PII.

**Request:** `multipart/form-data`

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `file` | file | — | Yes | PDF, JPEG, or PNG file to sanitize |
| `level` | string | `standard` | No | Sanitization level: `standard` or `strict` |
| `response_format` | string | `file` | No | Response format: `file`, `json`, or `full` |

**Response formats:**

| Format | Content-Type | Description |
|--------|-------------|-------------|
| `file` | Same as input (`application/pdf`, `image/jpeg`, `image/png`) | Sanitized file as binary download. Findings in `X-Saniflow-Findings` response header as JSON. |
| `json` | `application/json` | Findings and summary only (no file content). |
| `full` | `application/json` | Findings, summary, and sanitized file as base64-encoded string in `file` field. |

**Example: Sanitize a PDF and get the redacted file**

```bash
curl -X POST http://localhost:8000/api/v1/sanitize \
  -F "file=@contract.pdf" \
  -F "level=standard" \
  -F "response_format=file" \
  -o contract_sanitized.pdf
```

**Example: Get findings as JSON (strict mode)**

```bash
curl -X POST http://localhost:8000/api/v1/sanitize \
  -F "file=@document.pdf" \
  -F "level=strict" \
  -F "response_format=json"
```

**JSON response shape** (`json` and `full` formats):

```json
{
  "findings": [
    {
      "entity_type": "PERSON_NAME",
      "original_text": "Juan Perez",
      "score": 0.85,
      "page": 1,
      "bbox": {"x0": 72.0, "y0": 100.0, "x1": 200.0, "y1": 115.0}
    },
    {
      "entity_type": "DNI_NIE",
      "original_text": "12345678Z",
      "score": 0.95,
      "page": 1,
      "bbox": {"x0": 72.0, "y0": 130.0, "x1": 180.0, "y1": 145.0}
    },
    {
      "entity_type": "FACE",
      "original_text": null,
      "score": 0.97,
      "page": 1,
      "bbox": {"x0": 400.0, "y0": 50.0, "x1": 500.0, "y1": 180.0}
    }
  ],
  "summary": {
    "total_findings": 3,
    "by_type": {"PERSON_NAME": 1, "DNI_NIE": 1, "FACE": 1},
    "level_applied": "strict"
  },
  "file": "JVBERi0xLjQ..."
}
```

The `file` field is only present in `full` format. Fields `original_text`, `page`, and `bbox` may be `null` depending on the entity type and detection source.

**Example: Sanitize an image with full response**

```bash
curl -X POST http://localhost:8000/api/v1/sanitize \
  -F "file=@photo.jpg" \
  -F "level=strict" \
  -F "response_format=full"
```

**Error responses:**

| Status | Condition | Response Body |
|--------|-----------|---------------|
| 413 | File exceeds max size (default 20 MB) | `{"detail": "File exceeds maximum size of 20 MB"}` |
| 415 | Unsupported MIME type | `{"detail": "Unsupported file type: application/msword"}` |
| 422 | Invalid level, format, or corrupted file | `{"detail": "File is corrupted or unreadable"}` |
| 500 | Internal processing error | `{"detail": "Internal processing error"}` |

#### `GET /api/v1/health`

Returns service health status.

```bash
curl http://localhost:8000/api/v1/health
```

```json
{"status": "healthy", "version": "0.1.0"}
```

### 7.2 Future API Endpoints

| R-ID | Endpoint | Method | Description | Priority |
|------|----------|--------|-------------|----------|
| R-API-01 | `/api/v1/sanitize/batch` | POST | Accept multiple files in a single request, return results as ZIP or JSON array | P2 |
| R-API-02 | `/api/v1/jobs/{id}` | GET | Check status of async sanitization jobs (for large files or batch processing) | P2 |
| R-API-03 | `/api/v1/policies` | CRUD | Create, read, update, delete custom sanitization policies (entity selection, thresholds) | P3 |
| R-API-04 | `/api/v1/audit` | GET | Query audit trail of past sanitization operations (requires persistence layer) | P3 |
| R-API-05 | `/api/v1/ws/sanitize` | WebSocket | Real-time progress for large file processing: extraction %, detection %, sanitization % | P4 |

---

## 8. Technical Architecture

### 8.1 Pipeline Architecture

```
                    ┌──────────┐
                    │  Upload   │  Client sends file via multipart/form-data
                    └────┬─────┘
                         │
                         ▼
                    ┌──────────┐
                    │ Validate  │  Check MIME type, file size, file integrity
                    └────┬─────┘
                         │
                         ▼
                 ┌───────────────┐
                 │  Orchestrator  │  Resolve file type → select extractor/sanitizer chain
                 └───────┬───────┘
                         │
              ┌──────────┼──────────┐
              ▼          ▼          ▼
         ┌─────────┐ ┌────────┐ ┌──────────┐
         │ Extract  │ │ Detect │ │ Sanitize │
         │ (text +  │ │ (PII)  │ │ (redact) │
         │ coords)  │ │        │ │          │
         └─────────┘ └────────┘ └──────────┘
              │          │          │
              ▼          ▼          ▼
         SpanMap    Findings    Sanitized
         built     generated   bytes out
```

**Stage details:**

1. **Upload & Validate** (`app/api/routes.py`): FastAPI receives the multipart upload. Validates MIME type against `SUPPORTED_FORMATS`, checks file size against `MAX_FILE_SIZE` (20MB default), validates `level` and `response_format` parameters.

2. **Orchestrate** (`app/pipeline/orchestrator.py`): The `SanitizationPipeline` class resolves whether the input is a PDF or image (extension check + magic bytes fallback), then chains the correct extractor, detector(s), and sanitizer.

3. **Extract** (`app/pipeline/extractors/`): Pulls text content with position metadata from the source file. For PDFs, uses PyMuPDF `get_text("dict")` to walk blocks -> lines -> spans, building a `SpanMap` that tracks cumulative character offsets to bounding boxes. For images, uses pytesseract `image_to_data` for OCR with bounding boxes. If a PDF page has no native text, falls back to OCR via `get_textpage_ocr(language="spa")`.

4. **Detect** (`app/pipeline/detectors/`): Runs Presidio Analyzer on the extracted text with Spanish NLP. The `TextPiiDetector` maps Presidio character offsets back to page coordinates via the SpanMap. If level is `strict`, the `VisualDetector` additionally runs YuNet face detection and connected component signature analysis on extracted images.

5. **Sanitize** (`app/pipeline/sanitizers/`): For PDFs, applies PyMuPDF real redaction (`add_redact_annot` + `apply_redactions`) which permanently removes content. For images, draws filled black rectangles over detected regions using OpenCV/Pillow.

6. **Output** (`app/api/routes.py`): Based on `response_format`, returns the sanitized file as binary stream, JSON findings, or both (with base64-encoded file).

### 8.2 Module Design

| Module | Responsibility | Key Classes | File Path |
|--------|---------------|-------------|-----------|
| API Layer | HTTP endpoints, validation, response building | `router`, `sanitize()`, `health()` | `app/api/routes.py` |
| API Schemas | Pydantic models for request/response | `FindingResponse`, `SanitizeResponse`, `SanitizeFullResponse`, `ErrorResponse` | `app/api/schemas.py` |
| Config | Environment-based settings with Pydantic | `Settings` | `app/config.py` |
| Domain Models | Core data structures | `Finding`, `EntityType`, `SanitizationLevel`, `SanitizationResult`, `FindingSummary` | `app/models/findings.py` |
| Extraction Models | SpanMap + extraction results | `SpanMap`, `SpanInfo`, `ExtractionResult`, `ExtractedImage` | `app/models/extraction.py` |
| Orchestrator | Pipeline coordination, file type resolution | `SanitizationPipeline` | `app/pipeline/orchestrator.py` |
| PDF Extractor | Text + image extraction from PDFs | `PdfExtractor` | `app/pipeline/extractors/pdf.py` |
| Image Extractor | OCR + image loading | `ImageExtractor` | `app/pipeline/extractors/image.py` |
| Text Detector | Presidio-based PII detection | `TextPiiDetector` | `app/pipeline/detectors/text_pii.py` |
| Visual Detector | Face + signature detection | `VisualDetector` | `app/pipeline/detectors/visual.py` |
| Custom Recognizers | Spanish phone + address patterns | `EsPhoneRecognizer`, `EsAddressRecognizer` | `app/pipeline/detectors/recognizers/` |
| PDF Sanitizer | PyMuPDF real redaction | `PdfSanitizer` | `app/pipeline/sanitizers/pdf.py` |
| Image Sanitizer | Rectangle fill redaction | `ImageSanitizer` | `app/pipeline/sanitizers/image.py` |

### 8.3 SpanMap -- The Critical Innovation

**The problem:** Presidio operates on plain text and returns character offsets (e.g., "PII found at characters 42-51"). But to redact in a PDF, we need **page coordinates** (bounding boxes). The text Presidio analyzes is a concatenation of hundreds of text spans extracted from the PDF, each at different positions on different pages.

**The solution:** `SpanMap` — a data structure built during extraction that creates a bidirectional mapping between cumulative character offsets and PDF coordinates.

**How it works:**

1. During extraction, `PdfExtractor` walks through PyMuPDF's `get_text("dict")` output: blocks -> lines -> spans.
2. For each span, `SpanMap.append(SpanInfo(text, bbox, page))` is called, recording the span's text, bounding box, and page number at the current cursor position.
3. Separators (newlines between lines and blocks) advance the cursor via `SpanMap.advance()`.
4. After extraction, Presidio analyzes the concatenated text.
5. For each Presidio result, `SpanMap.resolve(start, end)` uses `bisect_right` for O(log n) lookup to find all spans overlapping with the detected character range, returning `(page, bbox)` pairs.

**Edge cases handled:**
- **Multi-span PII**: A name split across two font spans returns multiple bounding boxes — each gets a separate redaction annotation.
- **Multi-column layouts**: PyMuPDF reads in document order; SpanMap follows the same order, so offsets stay aligned.
- **Rotated text**: PyMuPDF accounts for rotation in bbox coordinates; SpanMap captures whatever bbox PyMuPDF reports.
- **OCR fallback**: For scanned pages, OCR word boxes are registered in the SpanMap the same way as native text spans.

### 8.4 Technology Stack

| Component | Technology | Version | Rationale |
|-----------|-----------|---------|-----------|
| Language | Python | 3.12+ | Ecosystem support for NLP, PDF processing, and computer vision |
| Web framework | FastAPI | >= 0.115 | Async support, automatic OpenAPI docs, Pydantic integration |
| ASGI server | Uvicorn | >= 0.34 | Standard production server for FastAPI |
| PII detection | Presidio Analyzer | >= 2.2 | Modular, extensible, supports custom recognizers and multiple NLP backends |
| NLP backend | spaCy (`es_core_news_md`) | >= 3.8 | Best tradeoff for Spanish NER: good accuracy without bloating Docker image (~50MB vs ~500MB for `_lg`) |
| PDF processing | PyMuPDF (fitz) | >= 1.25 | Real redaction support, text extraction with coordinates, built-in OCR integration |
| OCR | Tesseract OCR + pytesseract | >= 0.3.13 | Industry standard OCR, good Spanish support via `tesseract-ocr-spa` |
| Computer vision | OpenCV (headless) | >= 4.10 | Face detection (YuNet built-in), image processing, no GUI dependencies |
| Image processing | Pillow | >= 11.0 | Image loading, format conversion, drawing primitives |
| Configuration | Pydantic Settings | >= 2.7 | Type-safe, env var loading, validation on startup, 12-factor compatible |
| File upload | python-multipart | >= 0.0.18 | Required by FastAPI for multipart/form-data parsing |
| Testing | pytest + pytest-asyncio | >= 8.3 | Async test support for FastAPI endpoints |
| HTTP test client | httpx | >= 0.28 | Required by FastAPI TestClient |
| Containerization | Docker + docker-compose | — | Reproducible builds, system dependency management |

### 8.5 Docker Architecture

```dockerfile
FROM python:3.12-slim                          # ~150MB base

# System layer: Tesseract + Spanish + OpenCV deps + poppler
RUN apt-get install tesseract-ocr tesseract-ocr-spa libgl1 libglib2.0-0 poppler-utils curl

# Python deps layer (cached unless pyproject.toml changes)
COPY pyproject.toml .
RUN pip install --no-cache-dir .

# Model layer: spaCy + YuNet (cached unless explicitly rebuilt)
RUN python -m spacy download es_core_news_md   # ~50MB
RUN curl -L -o /app/models/yunet.onnx ...      # ~340KB

# Application layer (changes frequently)
COPY app/ /app/app/

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

**Layer strategy:** System deps and models are in early layers (rarely change, cached). Application code is in the last layer (fast rebuilds during development).

**Estimated image size:** ~1.5-2 GB (breakdown: Python slim ~150MB, system packages ~200MB, Python packages ~600MB, spaCy model ~50MB, OpenCV ~400MB, PyMuPDF + Presidio ~200MB).

**Docker Compose** defines a single service with health check (`curl -f http://localhost:8000/api/v1/health`), env file loading, and a named volume for temp file storage.

---

## 9. Security & Privacy

### 9.1 Core Principles

| R-ID | Principle | Implementation |
|------|-----------|----------------|
| R-SEC-01 | **Zero data retention** | Stateless processing. No database, no file storage, no session state. Files exist only in memory during processing. |
| R-SEC-02 | **Real redaction** | PyMuPDF `apply_redactions()` permanently removes content from the PDF. Not a visual overlay — the underlying text and graphics are irretrievably deleted. |
| R-SEC-03 | **No external API calls** | All PII detection runs locally: Presidio + spaCy NLP models, OpenCV YuNet, Tesseract OCR. No data leaves the server. |
| R-SEC-04 | **No PII in logs** | Error messages are generic ("Internal processing error"). Detected PII text is logged only at DEBUG level, never in production. |
| R-SEC-05 | **Minimal error exposure** | HTTP 500 responses contain no stack traces or internal details. Errors are logged server-side only. |

### 9.2 Redaction Guarantee

**PyMuPDF real redaction** is a two-step process:

1. `page.add_redact_annot(rect, fill=(0,0,0))` — marks the area for redaction with a black fill.
2. `page.apply_redactions()` — **permanently removes** all text and vector graphics underneath the marked areas. The content is deleted from the PDF's internal structure, not just covered.

This is fundamentally different from drawing a black rectangle on top of text (which can be removed by anyone with a PDF editor).

**Known issue: PyMuPDF #2762.** After applying redactions, some text OUTSIDE redaction areas may disappear in certain PDF structures. This is a known upstream issue. Mitigation: test with real documents before production deployment; verify output documents preserve non-redacted content. The risk is low but non-zero.

**Image redaction** uses filled rectangles via OpenCV/Pillow. Since images don't have an underlying text layer, pixel replacement is a complete redaction.

### 9.3 Future Security Features

| R-ID | Feature | Priority | Description |
|------|---------|----------|-------------|
| R-SEC-06 | Temp file encryption | P2 | Encrypt any temporary files written to disk during processing |
| R-SEC-07 | Memory-only processing | P2 | Ensure all processing happens in memory with no disk writes |
| R-SEC-08 | mTLS for API | P3 | Mutual TLS for service-to-service communication |
| R-SEC-09 | API key authentication | P3 | Require API keys for access, with per-key rate limits |
| R-SEC-10 | Audit logging | P3 | Structured audit trail: who sanitized what, when, what was found (without storing the PII itself) |
| R-SEC-11 | SOC 2 compliance path | P4 | Documentation and controls for SOC 2 Type II certification |

---

## 10. Deployment & Operations

### 10.1 Local Development

Requirements: Python 3.12+, Tesseract OCR with Spanish language pack, YuNet ONNX model.

```bash
# Install dependencies
pip install -e ".[dev]"

# Download spaCy model
python -m spacy download es_core_news_md

# Download YuNet model
mkdir -p models
curl -L -o models/face_detection_yunet_2023mar.onnx \
  https://github.com/opencv/opencv_zoo/raw/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx

# Set model path for local dev
export SANIFLOW_YUNET_MODEL_PATH=models/face_detection_yunet_2023mar.onnx

# Run the server
uvicorn app.main:app --reload
```

### 10.2 Docker Deployment

```bash
cp .env.example .env    # Configure environment variables
docker compose up --build
```

The service is available at `http://localhost:8000`. Health check runs every 30 seconds with a 30-second start period to allow model loading.

### 10.3 Configuration Reference

All environment variables are prefixed with `SANIFLOW_`.

| Variable | Default | Description |
|----------|---------|-------------|
| `SANIFLOW_MAX_FILE_SIZE` | `20971520` (20 MB) | Maximum upload file size in bytes |
| `SANIFLOW_SUPPORTED_FORMATS` | `["application/pdf","image/jpeg","image/png"]` | Accepted MIME types |
| `SANIFLOW_DEFAULT_LEVEL` | `standard` | Default sanitization level |
| `SANIFLOW_CONFIDENCE_THRESHOLD_REGEX` | `0.7` | Minimum confidence for regex-based detections |
| `SANIFLOW_CONFIDENCE_THRESHOLD_NER` | `0.5` | Minimum confidence for NER-based detections |
| `SANIFLOW_TESSERACT_LANG` | `spa` | Tesseract OCR language code |
| `SANIFLOW_SPACY_MODEL` | `es_core_news_md` | spaCy NLP model for entity recognition |
| `SANIFLOW_YUNET_MODEL_PATH` | `/app/models/face_detection_yunet_2023mar.onnx` | Path to YuNet face detection ONNX model |
| `SANIFLOW_TEMP_DIR` | `/tmp/saniflow` | Temporary file directory |

### 10.4 Future Deployment Options

| R-ID | Option | Priority | Notes |
|------|--------|----------|-------|
| R-DEP-01 | Kubernetes (Helm chart) | P2 | Horizontal scaling, health probes, resource limits |
| R-DEP-02 | AWS ECS / Fargate | P3 | Serverless container deployment |
| R-DEP-03 | SaaS hosted | P4 | Multi-tenant hosted version with API key management |

---

## 11. Integration Roadmap

### 11.1 MCP Server (R-INT-01, Priority: High)

**What it enables:** AI tools (Claude, ChatGPT, custom agents) consume documents through Saniflow automatically. The AI never sees unsanitized content.

**How it would work:**
1. Saniflow exposes an MCP-compatible interface alongside (or instead of) the REST API.
2. AI tools register Saniflow as a document processing resource.
3. When an AI needs to read a document, it calls Saniflow's MCP endpoint.
4. Saniflow sanitizes the document and returns clean content to the AI.

**Which AI tools benefit:** Claude (via MCP), any LangChain/LlamaIndex pipeline, custom AI agents with tool-use capabilities, RAG systems that ingest documents.

### 11.2 Webhook Integration (R-INT-02, Priority: Medium)

POST sanitized results to external URLs upon completion. Enables event-driven architectures where sanitization is a step in a larger workflow.

### 11.3 SDK / Client Libraries (R-INT-03, Priority: Medium)

| SDK | Priority | Description |
|-----|----------|-------------|
| Python | P2 | `pip install saniflow-client` — typed client with async support |
| TypeScript | P2 | `npm install @saniflow/client` — for Node.js and browser-based integrations |
| Go | P3 | For high-performance pipeline integrations |

---

## 12. Roadmap

### Phase 1: MVP (Current -- v0.1.0)

**Status: Implemented**

- FastAPI application with Pydantic configuration
- Pipeline orchestrator with Protocol-based abstractions
- PDF extraction with SpanMap coordinate mapping
- Image extraction with OCR (pytesseract)
- Text PII detection via Presidio (PERSON, DNI/NIE, EMAIL, PHONE, IBAN, ADDRESS)
- Visual PII detection: YuNet faces + connected component signatures
- PDF real redaction via PyMuPDF
- Image redaction via OpenCV/Pillow
- Three response formats: file, json, full
- Two sanitization levels: standard, strict
- Docker + docker-compose deployment
- Health check endpoint

### Phase 2: Hardening (v0.2.0)

- Upgrade to `es_core_news_lg` spaCy model for better Spanish NER accuracy
- Improved address detection (ML-based or expanded regex patterns)
- Signature detection improvements (reduce false positives)
- Real document testing suite with diverse Spanish document types
- Performance benchmarks and optimization
- Input validation hardening (malformed PDFs, adversarial inputs)
- Structured logging with correlation IDs

### Phase 3: Production Ready (v0.3.0)

- API key authentication (header-based)
- Rate limiting (per-key and global)
- Async processing with FastAPI background tasks for large files
- Basic audit trail (what was processed, when, what was found -- no PII stored)
- Processing history with optional database (PostgreSQL)
- Prometheus metrics endpoint
- Health dashboard (processing counts, latency percentiles, error rates)

### Phase 4: Multi-tenant (v0.4.0)

- Organization accounts with API key management
- Configurable sanitization policies per organization
- Custom entity types (company-specific patterns)
- Usage tracking and quotas
- Billing integration (Stripe)
- Admin API for organization management

### Phase 5: AI Integration (v0.5.0)

- MCP server implementation
- Webhook support (POST results to external URLs)
- Python SDK (`saniflow-client`)
- TypeScript SDK (`@saniflow/client`)
- AI pipeline middleware (LangChain, LlamaIndex integration)
- Streaming API for real-time progress

### Phase 6: Enterprise (v1.0.0)

- Web frontend for manual sanitization and review
- Admin dashboard with analytics
- GDPR compliance presets (all Article 4 personal data categories)
- HIPAA Safe Harbor presets (18 identifiers)
- On-premise deployment guide and support
- SLA guarantees (99.9% uptime, < 5s processing for standard documents)
- SOC 2 Type II certification path

---

## 13. Non-Functional Requirements

### Performance

| R-ID | Requirement | Target | Notes |
|------|------------|--------|-------|
| R-PERF-01 | Max processing time (10-page native PDF, standard) | < 5 seconds | Excludes OCR time |
| R-PERF-02 | Max processing time (10-page native PDF, strict) | < 10 seconds | Includes face detection on embedded images |
| R-PERF-03 | Max processing time (single image, strict) | < 3 seconds | OCR + face detection |
| R-PERF-04 | Max processing time (scanned PDF per page) | < 10 seconds/page | OCR is ~1000x slower than text extraction |
| R-PERF-05 | Max upload file size | 20 MB (configurable) | Prevents memory exhaustion |
| R-PERF-06 | Peak memory usage per request | < 500 MB | For a 20MB PDF with embedded images |

### Reliability

| R-ID | Requirement | Implementation |
|------|------------|----------------|
| R-REL-01 | Graceful error handling | All pipeline errors caught and returned as HTTP 422/500 with generic messages |
| R-REL-02 | No partial output | If any pipeline stage fails, the entire request fails cleanly — no half-redacted documents |
| R-REL-03 | Corrupt file detection | Validate file integrity before processing; return 422 for unreadable files |
| R-REL-04 | Idempotent processing | Same input always produces same output (deterministic pipeline) |
| R-REL-05 | Lazy model loading | Presidio analyzer and spaCy model loaded on first request, not at startup (avoids slow cold starts blocking health checks) |

### Scalability

| Phase | Approach |
|-------|----------|
| MVP (current) | Single instance, synchronous processing, one request at a time per worker |
| v0.3.0 | Multiple Uvicorn workers, async processing with background tasks |
| v0.4.0 | Horizontal scaling with Kubernetes, shared-nothing architecture (stateless by design) |
| Future | Worker pool with task queue (Celery/Redis or similar) for CPU-intensive OCR and detection |

### Observability

| R-ID | Requirement | Status |
|------|------------|--------|
| R-OBS-01 | Structured logging (Python logging) | Implemented |
| R-OBS-02 | Health check endpoint | Implemented (`GET /api/v1/health`) |
| R-OBS-03 | Prometheus metrics | Planned (v0.3.0) |
| R-OBS-04 | Distributed tracing (OpenTelemetry) | Planned (v0.4.0) |
| R-OBS-05 | Error tracking (Sentry) | Planned (v0.3.0) |

---

## 14. Known Limitations & Risks

| ID | Limitation | Severity | Impact | Mitigation |
|----|-----------|----------|--------|------------|
| L-01 | **PyMuPDF #2762**: Text outside redaction areas may disappear after `apply_redactions()` on some PDF structures | Medium | Non-redacted content could be lost in output | Test with real documents; monitor upstream fix; consider pre/post diff validation |
| L-02 | **Spanish NER accuracy**: `es_core_news_md` misses some Spanish names, especially uncommon ones or names in unusual contexts | Medium | PII leaks through | Upgrade to `es_core_news_lg` in v0.2.0; add name dictionary fallback |
| L-03 | **Address detection low confidence**: Custom regex covers ~50-60% of Spanish address formats | High | Many addresses will not be detected | Strict mode only for now; ML-based approach planned for v0.2.0 |
| L-04 | **Signature detection experimental**: Connected component heuristic has ~50-60% precision | Medium | False positives (stamps, logos misidentified); false negatives (light signatures missed) | Marked as experimental; YOLO-based approach planned for future |
| L-05 | **Docker image size**: ~1.5-2 GB due to Tesseract, spaCy models, OpenCV | Low | Slower deployments, higher storage costs | Multi-stage builds; investigate Alpine base; lazy model loading |
| L-06 | **OCR performance**: Scanned PDFs process ~1000x slower than native text | Medium | Timeouts on large scanned documents | Warn in response; future: async processing with job queue |
| L-07 | **Single language**: Only Spanish NLP is configured | Medium | Cannot sanitize English, French, or other language documents | Multi-language support planned; Presidio supports it natively |
| L-08 | **No authentication**: MVP has no auth layer | High (for production) | Anyone with network access can use the API | API keys in v0.3.0; intended for internal/trusted networks in MVP |
| L-09 | **Synchronous processing**: Blocks on large files | Medium | Slow responses for large documents | Async background tasks in v0.3.0 |
| L-10 | **Context-dependent detection**: Presidio's Spanish context words default to English | Low | Some detections may have lower confidence without proper context | Custom context words configured for phone and address recognizers |

---

## 15. Success Metrics

| Metric | Target | Measurement Method |
|--------|--------|--------------------|
| PII detection recall (text, high-confidence entities: DNI, email, IBAN, phone) | > 95% | Test suite with known PII documents |
| PII detection recall (text, NER-based: names) | > 75% | Test suite with diverse Spanish names |
| PII detection recall (visual, faces) | > 85% | Test suite with document photographs |
| Processing time (10-page native PDF, standard) | < 5 seconds | Benchmark suite |
| Processing time (single image, strict) | < 3 seconds | Benchmark suite |
| False positive rate (text PII) | < 10% | Manual review of test corpus results |
| False positive rate (visual PII) | < 15% | Manual review of test corpus results |
| API availability (production) | 99.9% | Uptime monitoring |
| Docker build time (cached layers) | < 30 seconds | CI pipeline measurement |
| Docker build time (clean) | < 10 minutes | CI pipeline measurement |

---

## 16. Open Questions

| ID | Question | Context | Proposed Answer |
|----|----------|---------|-----------------|
| Q-01 | Multi-language support priority? | Currently Spanish-only. Presidio supports 30+ languages natively. | Add English as P1, then French, German, Portuguese. Configurable per request. |
| Q-02 | Should we support real-time streaming sanitization? | WebSocket for progress updates on large files | P3 — async job polling is simpler and sufficient for most use cases |
| Q-03 | HIPAA vs GDPR first for compliance presets? | Both have defined PII categories | GDPR first (European market focus), HIPAA second |
| Q-04 | Cloud vs on-premise as default deployment model? | SaaS is easier to monetize; on-premise is the privacy pitch | On-premise first (aligns with "your data stays with you" positioning), SaaS as optional |
| Q-05 | Pricing model for future SaaS tier? | Need to cover compute (OCR is CPU-intensive) | Per-document or per-page pricing; free tier for low volume |
| Q-06 | Should YuNet ONNX model be bundled in repo or downloaded at build time? | Currently downloaded via curl in Dockerfile | Keep download at build time — avoids bloating git repo with binary files |
| Q-07 | Minimum confidence thresholds per entity type? | Currently global: 0.7 regex, 0.5 NER | Per-entity thresholds in custom policies (v0.4.0) |
| Q-08 | Max file size limit for production? | Currently 20MB | May need to increase for batch processing; 50MB with async processing |

---

## 17. Competitive Landscape

| Solution | Type | PII Detection | Document Sanitization | Self-Hosted | Real Redaction | AI-Era Focus | Price |
|----------|------|--------------|----------------------|-------------|----------------|-------------|-------|
| **Saniflow** | Open source platform | Yes (text + visual) | Yes (PDF + images) | Yes | Yes (PyMuPDF) | Yes (MCP planned) | Free |
| AWS Comprehend | Cloud API | Text only | No | No | N/A | No | Pay per character |
| Google Cloud DLP | Cloud API | Text only | No (inspect only) | No | N/A | No | Pay per item |
| Microsoft Presidio | Library | Text only | No (detection only) | Yes (lib) | N/A | No | Free |
| Private AI | Commercial SaaS | Text + visual | Limited | Cloud only | Unknown | No | Enterprise pricing |
| Adobe Acrobat Pro | Desktop app | No (manual) | Yes (manual) | Desktop | Yes | No | $22.99/mo |
| DocuSign CLM | Enterprise | Limited | Limited | No | Overlay | No | Enterprise pricing |

**Saniflow's differentiation:**

1. **Complete pipeline**: Detection AND sanitization in one API call (not just detection like Presidio/Comprehend).
2. **Real redaction**: Content is permanently removed from PDFs, not just visually covered.
3. **Self-hosted**: Your documents never leave your infrastructure. Unlike cloud DLP services, you don't send PII to a third party to detect PII.
4. **AI-native**: Built for the AI era. MCP server integration means AI tools consume only sanitized content automatically.
5. **Open source**: Inspect the code, verify the redaction, extend with custom recognizers. No black boxes.
6. **Visual + text PII**: Face and signature detection alongside text PII — not just pattern matching.

---

*This PRD is the single source of truth for the Saniflow project. All implementation decisions should reference the requirement IDs (R-XXX-XX) defined herein. Updated as the project evolves.*
