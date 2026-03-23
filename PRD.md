# PRD: Saniflow

> **The sanitization layer between your documents and AI — detect, redact, and forget.**

**Version**: 0.1.0-draft
**Author**: Gentleman Programming
**Date**: 2026-03-23
**Status**: Draft

---

## 1. Problem Statement

The AI era has created a blind spot in data privacy. Every day, companies upload contracts, invoices, medical records, and ID documents to AI models — GPT, Claude, Gemini, internal LLMs — without removing personally identifiable information (PII) first. The document goes in with names, DNIs, IBANs, faces, and signatures. The AI processes it. The data is now outside the company's control.

**The real problem is threefold:**

1. **Regulatory exposure.** GDPR (Art. 5, 6, 9), LOPD-GDD, and sector-specific regulations (healthcare, finance) impose strict obligations on PII processing. Sending unsanitized documents to third-party AI services is, in many cases, a data breach by definition. Fines under GDPR reach 4% of global annual revenue or EUR 20M.

2. **No practical tooling exists.** Current solutions fall into three inadequate categories:
   - **Manual redaction** (Adobe Acrobat, PDF editors): slow, error-prone, does not scale to AI pipelines.
   - **Cloud PII detection** (AWS Comprehend, Google DLP): identifies PII but does not sanitize documents. Requires sending data to yet another cloud service — defeating the purpose.
   - **Visual overlays**: many tools draw black rectangles over PII but leave the underlying text intact. A simple copy-paste or text extraction recovers everything. This is security theater, not redaction.

3. **AI pipelines have no sanitization step.** Modern AI workflows — RAG systems, document Q&A, automated analysis — lack a standardized "sanitize before sending" middleware. The result: PII leaks at scale, silently.

**When PII leaks through:**
- Legal: regulatory fines, lawsuits, mandatory breach notifications
- Financial: remediation costs, lost contracts, insurance claims
- Reputational: customer trust erosion, public disclosure requirements
- Operational: incident response, forensic analysis, policy overhaul

Saniflow exists because this problem is not theoretical — it is happening today in every company that uses AI on documents.

---

## 2. Vision

**Saniflow becomes the standard sanitization layer between documents and AI.**

It sits at the boundary — after your application receives a document and before that document reaches any AI model, third-party API, or external system. Documents go in dirty; they come out clean. No PII leaves the perimeter.

### Before Saniflow

```
User uploads contract.pdf
  → Your app sends it to GPT-4 for summarization
  → GPT-4 processes: names, DNIs, IBANs, addresses, faces in photos
  → PII is now in OpenAI's infrastructure
  → You are in violation of GDPR Article 5(1)(c)
```

### After Saniflow

```
User uploads contract.pdf
  → Your app sends it to Saniflow (self-hosted, local)
  → Saniflow detects 12 PII entities, redacts all of them
  → Your app sends contract_sanitized.pdf to GPT-4
  → GPT-4 processes: [REDACTED], no PII exposed
  → Compliance maintained, zero data leakage
```

### The MCP Vision

Saniflow's roadmap includes an **MCP (Model Context Protocol) server**. AI tools — coding assistants, document analyzers, RAG pipelines — will consume only pre-sanitized content through a standard protocol. The AI never sees raw PII. This is not an afterthought; it is the end state: **AI-native sanitization as a service**.

---

## 3. Target Users

| Segment | Description | Pain Point | Saniflow Value |
|---------|-------------|------------|----------------|
| **Primary**: Companies using AI on documents | Legal firms, consultancies, HR departments, healthcare, finance | Sending contracts/reports/records to AI models with PII intact | Drop-in API that sanitizes before AI processing |
| **Secondary**: Developers building AI pipelines | Backend engineers, ML engineers, platform teams | No sanitization middleware exists for their RAG/LLM pipelines | Single API call integrates into any pipeline |
| **Secondary**: Compliance teams | DPOs, legal, security officers | Cannot verify that documents are sanitized before external sharing | JSON findings report as audit evidence |
| **Tertiary**: Freelancers & individuals | Consultants handling client documents | Need to share documents without exposing client PII | Simple upload-and-download workflow |

---

## 4. Supported Document Types

### Current MVP

| Type | Formats | MIME Types | Priority | Notes |
|------|---------|------------|----------|-------|
| PDF | `.pdf` (native text + scanned) | `application/pdf` | P0 | Real redaction via PyMuPDF; OCR fallback for scanned pages |
| Images | `.jpg`, `.jpeg`, `.png` | `image/jpeg`, `image/png` | P0 | OCR for text extraction; pixel-level redaction |

**[R-DOC-01]** The system MUST accept PDF, JPEG, and PNG files.
**[R-DOC-02]** The system MUST reject unsupported formats with HTTP 415.
**[R-DOC-03]** The system MUST enforce a configurable max file size (default: 20 MB) and reject oversized files with HTTP 413.
**[R-DOC-04]** The system MUST validate file integrity and reject corrupted files with HTTP 422.

### Future Formats

| Type | Formats | Priority | Rationale |
|------|---------|----------|-----------|
| Word | `.docx` | P1 | Most common business document format after PDF |
| Excel | `.xlsx` | P1 | Financial data, HR spreadsheets |
| Plain text | `.txt`, `.csv` | P1 | Simple extraction, high demand in data pipelines |
| Email | `.eml`, `.msg` | P2 | Corporate communications with PII |
| Presentations | `.pptx` | P2 | Embedded text and images |
| HTML | `.html` | P3 | Web content sanitization |

---

## 5. PII Detection Capabilities

### 5.1 Text-Based PII Detection

| Entity Type | ID | Detection Method | Confidence | Example Patterns | Level |
|-------------|-----|-----------------|------------|------------------|-------|
| Person name | `PERSON_NAME` | spaCy `es_core_news_md` NER via Presidio | Medium (0.5-0.85) | "Juan Garcia Lopez", "Maria Fernandez" | Standard |
| DNI | `DNI_NIE` | Presidio `EsNifRecognizer` (regex + checksum) | High (0.9+) | `12345678Z`, `00000000T` | Standard |
| NIE | `DNI_NIE` | Presidio `EsNieRecognizer` (regex + checksum) | High (0.9+) | `X1234567L`, `Y0000000Z` | Standard |
| Email | `EMAIL` | Presidio `EmailRecognizer` + Spanish context words | High (0.9+) | `juan@empresa.com` | Standard |
| Phone | `PHONE` | Custom `EsPhoneRecognizer` (regex) | High (0.7+) | `+34 612 345 678`, `912 345 678` | Standard |
| IBAN | `IBAN` | Presidio `IbanRecognizer` (pattern + checksum) | High (0.9+) | `ES91 2100 0418 4502 0005 1332` | Standard |
| Address | `ADDRESS` | Custom `EsAddressRecognizer` (regex + context) | Low (0.4-0.6) | `Calle Mayor 15, 28001 Madrid` | Standard |

**[R-DET-01]** The system MUST detect all entity types listed above when processing in `standard` or `strict` level.
**[R-DET-02]** Detection confidence MUST be included in every finding as a float between 0.0 and 1.0.
**[R-DET-03]** Custom recognizers for Spanish phone numbers and addresses MUST use configurable confidence thresholds (default: 0.7 regex, 0.5 NER).

### 5.2 Visual PII Detection

| Entity Type | ID | Detection Method | Confidence | Level | Status |
|-------------|-----|-----------------|------------|-------|--------|
| Face | `FACE` | OpenCV YuNet (`FaceDetectorYN`) | High (0.9+ threshold) | Strict | Stable |
| Signature | `SIGNATURE` | Connected component analysis heuristic | Low-Medium (0.5-0.7) | Strict | Experimental |

**[R-VIS-01]** Face detection MUST use OpenCV YuNet with a configurable confidence threshold (default: 0.9).
**[R-VIS-02]** Visual PII detection MUST only execute when `level=strict`.
**[R-VIS-03]** Signature detection SHOULD be marked as experimental in documentation and API responses.

### 5.3 Detection Accuracy Expectations

| Entity Type | Expected Recall | Expected Precision | Notes |
|-------------|----------------|-------------------|-------|
| DNI/NIE | >98% | >99% | Checksum validation makes this highly reliable |
| IBAN | >98% | >99% | Pattern + checksum |
| Email | >95% | >98% | Well-defined pattern |
| Phone (Spanish) | >90% | >85% | Custom regex covers common formats; uncommon formats may be missed |
| Person name | >70% | >60% | `es_core_news_md` has moderate NER accuracy; context-dependent |
| Address | >50% | >40% | Highly variable format; regex covers common patterns only |
| Face | >85% | >90% | YuNet is mature; struggles with very small or heavily occluded faces |
| Signature | >60% | >50% | Heuristic approach; false positives with stamps, logos, handwriting |

These are honest estimates. Person names and addresses are the weakest detection categories due to the inherent complexity of Spanish NER and address variability.

---

## 6. Sanitization Levels

### 6.1 Standard Level

**[R-LVL-01]** Default level. Detects and redacts all text-based PII.

| Detects | Does NOT Detect |
|---------|-----------------|
| Person names | Faces in photographs |
| DNI/NIE | Signatures |
| Email addresses | |
| Phone numbers | |
| IBANs | |
| Addresses | |

**Use cases:** General document sanitization, AI pipeline preprocessing, sharing documents externally where photos are expected to remain.

### 6.2 Strict Level

**[R-LVL-02]** Everything in standard, plus visual PII detection.

| Detects (additional) | Method |
|----------------------|--------|
| Faces in photographs/images | YuNet face detector |
| Handwritten signatures | Connected component analysis |

**Use cases:** Maximum privacy — identity documents (DNI scans, passports), HR records with employee photos, contracts with signatures, medical records.

### 6.3 Future Levels

| Level | Description | Priority |
|-------|-------------|----------|
| **Custom** | User-configurable per-entity rules (e.g., "redact names and IBANs, skip addresses") | P2 |
| **Compliance** | GDPR or HIPAA presets with legally mandated entity coverage | P3 |
| **Enterprise** | Company-specific policies with custom entity types and thresholds | P4 |

---

## 7. API Design

### 7.1 Current API (MVP)

Base URL: `http://localhost:8000` (Docker Compose maps host port 8010 to container port 8000)

#### `POST /api/v1/sanitize`

Sanitize a document by detecting and redacting PII.

**Parameters** (multipart form data):

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `file` | file | — | Yes | PDF, JPEG, or PNG file to sanitize |
| `level` | string | `standard` | No | Sanitization level: `standard` or `strict` |
| `response_format` | string | `file` | No | Response format: `file`, `json`, or `full` |

**Response Formats:**

| Format | Content-Type | Description |
|--------|-------------|-------------|
| `file` | `application/pdf`, `image/jpeg`, `image/png` | Binary download of sanitized file. Findings included in `X-Saniflow-Findings` response header as JSON. |
| `json` | `application/json` | Findings and summary only, no file content. |
| `full` | `application/json` | Findings, summary, and the sanitized file as a base64-encoded string. |

**Example: Sanitize a PDF and get the file back**

```bash
curl -X POST http://localhost:8000/api/v1/sanitize \
  -F "file=@contract.pdf" \
  -F "level=standard" \
  -F "response_format=file" \
  -o contract_sanitized.pdf
```

**Example: Get findings as JSON**

```bash
curl -X POST http://localhost:8000/api/v1/sanitize \
  -F "file=@contract.pdf" \
  -F "level=strict" \
  -F "response_format=json"
```

**Example: Get both (file as base64 + findings)**

```bash
curl -X POST http://localhost:8000/api/v1/sanitize \
  -F "file=@photo.jpg" \
  -F "level=strict" \
  -F "response_format=full"
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

The `file` field is only present in `full` format. Fields `original_text`, `page`, and `bbox` may be `null` depending on entity type.

**Error Responses:**

| Status | Condition | Response Body |
|--------|-----------|---------------|
| 413 | File exceeds max size | `{"detail": "File exceeds maximum size of 20 MB"}` |
| 415 | Unsupported file type | `{"detail": "Unsupported file type: application/msword"}` |
| 422 | Invalid level, format, or corrupted file | `{"detail": "File is corrupted or unreadable"}` |
| 500 | Internal processing error | `{"detail": "Internal processing error"}` |

**[R-API-01]** The sanitize endpoint MUST accept multipart form data with the parameters above.
**[R-API-02]** The `file` response format MUST include findings in the `X-Saniflow-Findings` response header.
**[R-API-03]** Error responses MUST NOT leak internal details (stack traces, file paths, library names).

#### `GET /api/v1/health`

Returns service status.

```bash
curl http://localhost:8000/api/v1/health
```

```json
{"status": "healthy", "version": "0.1.0"}
```

**[R-API-04]** Health endpoint MUST return HTTP 200 with status and version.

### 7.2 Future API Endpoints

| Endpoint | Method | Priority | Description |
|----------|--------|----------|-------------|
| `/api/v1/sanitize/batch` | POST | P2 | Accept multiple files in one request |
| `/api/v1/jobs/{id}` | GET | P2 | Poll async job status for large files |
| `/api/v1/policies` | CRUD | P3 | Create/manage sanitization policies |
| `/api/v1/policies/{id}/sanitize` | POST | P3 | Sanitize using a specific policy |
| `/api/v1/audit` | GET | P3 | Query processing audit trail |
| `/api/v1/ws/sanitize` | WebSocket | P4 | Real-time streaming progress for large documents |

---

## 8. Technical Architecture

### 8.1 Pipeline Architecture

```
┌──────────┐    ┌───────────┐    ┌──────────┐    ┌───────────┐    ┌──────────┐
│  Upload   │───>│  Extract   │───>│  Detect   │───>│ Sanitize  │───>│  Output   │
│           │    │            │    │           │    │           │    │           │
│ Validate  │    │ Text+Imgs  │    │ Text PII  │    │ Real      │    │ File /    │
│ file type │    │ SpanMap    │    │ Visual PII│    │ redaction │    │ JSON /    │
│ file size │    │ OCR if     │    │ (strict)  │    │ Content   │    │ Full      │
│           │    │ scanned    │    │           │    │ removal   │    │           │
└──────────┘    └───────────┘    └──────────┘    └───────────┘    └──────────┘
```

**Upload**: FastAPI receives the file, validates MIME type, file size, and integrity. Fails fast with appropriate HTTP status codes.

**Extract**: The appropriate extractor (PDF or image) pulls text content with positional metadata. For PDFs, `PyMuPDF.get_text("dict")` provides span-level text with bounding boxes. For images, `pytesseract.image_to_data()` provides word-level OCR with coordinates. A `SpanMap` is built during this stage, mapping cumulative character offsets to page coordinates.

**Detect**: Presidio runs NLP-based and pattern-based entity recognition on the concatenated text. When `level=strict`, OpenCV YuNet runs face detection and connected component analysis runs signature detection on extracted images.

**Sanitize**: Findings with coordinates are applied as real redactions. PDFs use `PyMuPDF.add_redact_annot()` + `apply_redactions()` which permanently removes content. Images use `cv2.rectangle()` to fill detected regions with solid black.

**Output**: The response is built based on `response_format` — binary file download, JSON findings, or both.

### 8.2 Module Design

| Module | Responsibility | Key Classes | Path |
|--------|---------------|-------------|------|
| API Layer | HTTP routing, validation, response building | `router`, `sanitize()` | `app/api/routes.py` |
| API Schemas | Request/response Pydantic models | `SanitizeResponse`, `FindingResponse`, `ErrorResponse` | `app/api/schemas.py` |
| Config | Environment-driven settings | `Settings` | `app/config.py` |
| Domain Models | Core data structures | `Finding`, `EntityType`, `SanitizationLevel`, `SanitizationResult` | `app/models/findings.py` |
| Extraction Models | SpanMap, ExtractionResult | `SpanMap`, `SpanInfo`, `ExtractionResult` | `app/models/extraction.py` |
| Orchestrator | Pipeline coordination | `SanitizationPipeline` | `app/pipeline/orchestrator.py` |
| PDF Extractor | Text + image extraction from PDFs | `PdfExtractor` | `app/pipeline/extractors/pdf.py` |
| Image Extractor | OCR text extraction from images | `ImageExtractor` | `app/pipeline/extractors/image.py` |
| Text PII Detector | Presidio-based entity recognition | `TextPiiDetector` | `app/pipeline/detectors/text_pii.py` |
| Visual Detector | Face + signature detection | `VisualDetector` | `app/pipeline/detectors/visual.py` |
| Phone Recognizer | Spanish phone number patterns | `EsPhoneRecognizer` | `app/pipeline/detectors/recognizers/es_phone.py` |
| Address Recognizer | Spanish address patterns | `EsAddressRecognizer` | `app/pipeline/detectors/recognizers/es_address.py` |
| PDF Sanitizer | Real redaction on PDFs | `PdfSanitizer` | `app/pipeline/sanitizers/pdf.py` |
| Image Sanitizer | Pixel-level redaction on images | `ImageSanitizer` | `app/pipeline/sanitizers/image.py` |
| App Entry | FastAPI factory, lifespan, middleware | `app`, `lifespan()` | `app/main.py` |

### 8.3 SpanMap — The Critical Innovation

The hardest integration challenge in document sanitization is **mapping text detection results back to document coordinates**. Presidio operates on plain text and returns character offsets (e.g., "DNI found at chars 145-154"). But to redact in a PDF, you need pixel coordinates on a specific page.

**The problem**: PyMuPDF extracts text as hierarchical spans (blocks -> lines -> spans), each with a bounding box. Presidio receives concatenated plain text and has no concept of pages or coordinates. The mapping between "character 145 in the plain text" and "this rectangle on page 2" is non-trivial, especially with multi-column layouts, rotated text, or spans that break across lines.

**The solution**: `SpanMap` (defined in `app/models/extraction.py`).

During extraction, as each text span is processed, `SpanMap.append()` records the span's text, bounding box, page number, and its cumulative character offset in the concatenated text. Separators (newlines between lines and blocks) are tracked with `SpanMap.advance()`.

When Presidio returns a detection at `[start, end)`, `SpanMap.resolve(start, end)` uses `bisect.bisect_right()` for **O(log n)** lookup to find all spans whose character ranges overlap the detection range. It returns `(page, bbox)` pairs that the sanitizer uses for redaction.

**Key design decisions:**
- `bisect` for O(log n) lookup instead of linear scan
- Parallel `_offsets` list enables bisect without key functions
- Handles PII spanning multiple spans by returning all overlapping SpanRects
- Frozen `SpanInfo` dataclass with `__slots__` for immutability and memory efficiency

### 8.4 Technology Stack

| Component | Technology | Version | Rationale |
|-----------|-----------|---------|-----------|
| Language | Python | 3.12+ | Ecosystem compatibility with NLP/CV libraries |
| Web framework | FastAPI | >=0.115 | Async, auto-docs, Pydantic integration, production-ready |
| ASGI server | Uvicorn | >=0.34 | Standard ASGI server for FastAPI |
| PII detection | Presidio Analyzer | >=2.2 | Microsoft's battle-tested PII detection with extensible recognizers |
| PII anonymization | Presidio Anonymizer | >=2.2 | Companion library for redaction strategies |
| NLP | spaCy (`es_core_news_md`) | >=3.8 | Spanish NER for person names and contextual entity recognition |
| PDF processing | PyMuPDF (fitz) | >=1.25 | Fast PDF text extraction with coordinates + real redaction capability |
| OCR | Tesseract + pytesseract | System + >=0.3.13 | Industry-standard OCR with Spanish language support |
| Computer vision | OpenCV (headless) | >=4.10 | YuNet face detection, connected component analysis |
| Image processing | Pillow | >=11.0 | Image loading, format conversion |
| Configuration | Pydantic Settings | >=2.7 | Type-safe, env-var based, validates on startup |
| Multipart handling | python-multipart | >=0.0.18 | File upload parsing for FastAPI |
| Testing | pytest + pytest-asyncio | >=8.3, >=0.25 | Async test support for FastAPI |
| HTTP test client | httpx | >=0.28 | TestClient backend for FastAPI |
| Containerization | Docker | — | Reproducible builds with system deps (Tesseract) |
| Orchestration | Docker Compose | — | Single-command local deployment |

### 8.5 Docker Architecture

**Base image:** `python:3.12-slim`

**Layer breakdown:**

| Layer | Content | Estimated Size |
|-------|---------|---------------|
| Base image | Python 3.12 slim | ~150 MB |
| System deps | Tesseract OCR + Spanish pack, libgl1, libglib2.0, poppler-utils, curl | ~200 MB |
| Python deps | FastAPI, Presidio, PyMuPDF, OpenCV, Pillow, spaCy | ~600 MB |
| spaCy model | `es_core_news_md` | ~50 MB |
| YuNet model | `face_detection_yunet_2023mar.onnx` (downloaded at build time) | ~340 KB |
| Application code | `app/` directory | ~100 KB |
| **Total** | | **~1.0-1.5 GB** |

**Docker Compose configuration:**
- Host port 8010 mapped to container port 8000
- Named volume `saniflow-tmp` mounted at `/tmp/saniflow`
- Environment loaded from `.env` file
- Health check: `curl -f http://localhost:8000/api/v1/health` every 30s (3 retries, 30s start period)

---

## 9. Security & Privacy

### 9.1 Core Principles

**[R-SEC-01] Zero data retention.** The MVP is fully stateless. No uploaded file, extracted text, or detection result is persisted to disk or database. Files are processed in memory and discarded after the response is sent. The temp directory (`/tmp/saniflow`) is used only for intermediate processing and is not a persistence layer.

**[R-SEC-02] Real redaction, not overlays.** When Saniflow redacts a PDF, the underlying text content is permanently removed from the document structure using PyMuPDF's `add_redact_annot()` + `apply_redactions()`. This is irreversible by design. Copy-pasting from the redacted area yields nothing. Text extraction tools find nothing. The content is gone.

**[R-SEC-03] No external API calls for PII detection.** All detection runs locally — Presidio, spaCy, Tesseract, OpenCV. No document content is ever sent to an external service. This is a fundamental architectural constraint, not an optimization.

### 9.2 Redaction Guarantee

**PDF Redaction (PyMuPDF):**
PyMuPDF's two-step process — `add_redact_annot(rect)` then `apply_redactions()` — physically removes content from the PDF's internal structure. The `graphics=0` flag preserves vector graphics outside redacted areas while removing text within them. This is a different mechanism from annotation-based "redaction" that simply overlays a black box.

**Known issue: PyMuPDF #2762.** After applying redactions, some text OUTSIDE redaction areas has been reported to disappear in certain edge cases. Mitigation: thorough testing with diverse real documents, and documenting this as a known limitation. Future mitigation includes pre/post comparison validation.

**Image Redaction:**
For images, redaction fills detected regions with solid black rectangles at the pixel level (`cv2.rectangle`). The original pixel data in those regions is overwritten and unrecoverable.

### 9.3 Future Security Features

| Feature | Priority | Description |
|---------|----------|-------------|
| Encryption at rest for temp files | P2 | Encrypt any intermediate files written to disk |
| API key authentication | P3 | Prevent unauthorized access to the sanitization API |
| mTLS for API communication | P3 | Mutual TLS for service-to-service trust |
| Rate limiting | P3 | Prevent abuse and resource exhaustion |
| Request signing | P4 | Verify request integrity and origin |
| SOC 2 compliance path | P4 | Audit controls, access logging, change management |
| Secure temp file cleanup | P2 | Guarantee temp files are wiped even on crash |

---

## 10. Deployment & Operations

### 10.1 Local Development

Requires: Python 3.12+, Tesseract OCR with Spanish language pack, YuNet ONNX model file.

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

# Run tests
pytest
pytest -m "not slow"          # skip slow tests
pytest -m "not integration"   # unit tests only
```

### 10.2 Docker Deployment

```bash
cp .env.example .env
docker compose up --build
```

The API is available at `http://localhost:8010`. Health check is automatic via Docker Compose.

### 10.3 Future Deployment Options

| Option | Priority | Description |
|--------|----------|-------------|
| Kubernetes (Helm chart) | P3 | Horizontal scaling, auto-scaling based on CPU/memory |
| AWS ECS / Fargate | P3 | Managed container orchestration |
| Serverless (AWS Lambda) | P4 | Per-invocation pricing; constrained by cold start and memory limits |
| SaaS hosted | P4 | Multi-tenant hosted service with API keys and billing |
| On-premise appliance | P5 | Pre-configured VM/container for enterprise customers |

---

## 11. Integration Roadmap

### 11.1 MCP Server (Priority: High)

**What it enables:** AI tools — Claude, GPT-based assistants, coding agents, RAG systems — consume documents through the MCP protocol. Saniflow sits as an MCP server that intercepts document access and returns only sanitized content. The AI model never sees raw PII.

**How it would work:**
1. AI tool requests a document via MCP
2. Saniflow MCP server receives the request
3. Document is sanitized through the standard pipeline
4. Sanitized content is returned to the AI tool
5. Findings are logged for audit (optional)

**Which AI tools benefit:** Claude Desktop, Cursor, Windsurf, custom LLM agents, any MCP-compatible tool.

### 11.2 Webhook Integration

Post-sanitization webhooks would allow Saniflow to push results to external systems:
- Sanitized file uploaded to S3/GCS
- Findings report sent to a compliance dashboard
- Alerts on high-risk PII detection (many entities, specific types)

### 11.3 SDK / Client Libraries

| SDK | Priority | Description |
|-----|----------|-------------|
| Python | P2 | `pip install saniflow-client` — typed client with async support |
| TypeScript/JavaScript | P2 | `npm install @saniflow/client` — for Node.js and browser |
| Go | P3 | For backend services and CLI tools |

---

## 12. Roadmap

### Phase 1: MVP (Current -- v0.1.0)

**Status: Complete**

- FastAPI application with health and sanitize endpoints
- Pipeline orchestrator with pluggable extractor/detector/sanitizer stages
- PDF extraction with SpanMap coordinate mapping
- Image extraction with Tesseract OCR
- Text PII detection via Presidio: person names, DNI/NIE, email, phone, IBAN, address
- Visual PII detection: YuNet face detection, connected component signature detection
- PDF real redaction via PyMuPDF
- Image redaction via OpenCV
- Standard and strict sanitization levels
- Three response formats: file, JSON, full
- Docker and Docker Compose deployment
- Configuration via environment variables with Pydantic Settings
- CORS middleware enabled

### Phase 2: Hardening (v0.2.0)

- Upgrade spaCy model to `es_core_news_lg` for better Spanish NER accuracy
- Improve address detection with additional regex patterns and context heuristics
- Improve signature detection with contour-based approach
- Build a real document testing suite with diverse Spanish documents
- Performance benchmarks: processing time, memory usage, accuracy metrics
- Pre/post redaction validation (detect PyMuPDF #2762 side effects)
- Structured logging with correlation IDs

### Phase 3: Production Ready (v0.3.0)

- API key authentication (simple bearer token)
- Rate limiting (per-key and global)
- Async processing with FastAPI background tasks for large files
- Basic audit trail: what was sanitized, when, by whom (in-memory or SQLite)
- Processing history with optional database persistence
- Monitoring dashboard: health, request count, error rate, processing times
- OpenAPI documentation improvements

### Phase 4: Multi-tenant (v0.4.0)

- Company/organization accounts
- Configurable sanitization policies per tenant
- Custom entity types (company-specific PII definitions)
- Usage tracking and quotas
- Billing integration (Stripe)
- Tenant isolation guarantees

### Phase 5: AI Integration (v0.5.0)

- MCP server implementation
- Webhook support for post-processing events
- Python and TypeScript SDK client libraries
- AI pipeline middleware (LangChain, LlamaIndex integrations)
- Batch processing API
- Async job queue (Redis/RabbitMQ workers)

### Phase 6: Enterprise (v1.0.0)

- Web frontend for document upload and review
- Admin dashboard with analytics
- GDPR/HIPAA compliance presets
- On-premise deployment with Helm charts
- SLA guarantees (99.9% availability)
- SOC 2 Type II certification path
- Multi-language support (English, French, German, Portuguese)

---

## 13. Non-Functional Requirements

### Performance

| Requirement | ID | Target |
|-------------|-----|--------|
| PDF processing (10-page, native text) | R-PERF-01 | < 5 seconds |
| PDF processing (10-page, scanned/OCR) | R-PERF-02 | < 30 seconds |
| Image processing (single JPEG/PNG) | R-PERF-03 | < 3 seconds |
| Max concurrent requests (single instance) | R-PERF-04 | 5-10 (CPU-bound processing) |
| Memory per request (10-page PDF) | R-PERF-05 | < 500 MB peak |
| Max file size | R-PERF-06 | 20 MB (configurable) |

### Reliability

| Requirement | ID | Description |
|-------------|-----|-------------|
| Error isolation | R-REL-01 | A failed processing request MUST NOT affect other concurrent requests |
| Graceful degradation | R-REL-02 | If OCR fails, fall back to text-only extraction. If visual detection fails, return text findings only |
| Idempotent processing | R-REL-03 | Same file + same parameters MUST produce identical output |
| No data corruption | R-REL-04 | Output file MUST be valid (valid PDF, valid JPEG/PNG) |
| Catch-all error handler | R-REL-05 | Unhandled exceptions return generic 500, never leak internals |

### Scalability

| Phase | Architecture | Concurrency |
|-------|-------------|-------------|
| MVP (current) | Single Uvicorn instance | Limited by CPU cores; processing is synchronous |
| v0.3.0 | Background tasks | Async request handling with sync processing in thread pool |
| v0.5.0 | Worker queue | Celery/RQ workers for horizontal scaling |
| v1.0.0 | Kubernetes | Auto-scaling pods based on CPU/memory utilization |

### Observability

| Feature | MVP | v0.3.0 | v1.0.0 |
|---------|-----|--------|--------|
| Structured logging | Python `logging` | JSON logs with correlation IDs | ELK/Loki |
| Health checks | `GET /api/v1/health` | Dependency health (Tesseract, models loaded) | Deep health checks |
| Metrics | None | Prometheus endpoint | Full dashboard (Grafana) |
| Tracing | None | Request tracing | Distributed tracing (OpenTelemetry) |

---

## 14. Known Limitations & Risks

| ID | Limitation | Severity | Impact | Mitigation |
|----|-----------|----------|--------|------------|
| L-01 | PyMuPDF issue #2762: text outside redaction areas may disappear after `apply_redactions()` | High | Sanitized PDF may have unintended content removal | Extensive testing with diverse documents; pre/post text comparison validation (Phase 2) |
| L-02 | Spanish NER (`es_core_news_md`) has moderate accuracy for person names | Medium | Some names may be missed (~30% miss rate) | Upgrade to `es_core_news_lg` in Phase 2; combine with context-based heuristics |
| L-03 | Address detection has low confidence (~40-50% recall) | Medium | Many addresses will not be detected | Improve regex coverage in Phase 2; consider LLM-based detection in future |
| L-04 | Signature detection is experimental (heuristic-based) | Medium | False positives with stamps, logos, handwritten notes | Document as experimental; allow users to disable; improve in Phase 2 |
| L-05 | Docker image size ~1.0-1.5 GB | Low | Slower deployments, higher storage costs | Multi-stage build optimization; consider alpine base |
| L-06 | OCR on scanned PDFs is slow (~10x native text extraction) | Medium | 30+ second processing for scanned documents | Lazy OCR (only when native text is empty); future: async processing |
| L-07 | No multi-language support | Medium | Only works reliably for Spanish documents | Phase 6: add en, fr, de, pt models |
| L-08 | Synchronous processing blocks the worker | Medium | Limited concurrent request handling | Phase 3: background tasks; Phase 5: worker queue |
| L-09 | No authentication | High (for production) | Anyone with network access can use the API | Phase 3: API key auth |
| L-10 | No audit trail | Medium (for compliance) | Cannot prove what was sanitized, when, or by whom | Phase 3: basic audit logging |

---

## 15. Success Metrics

| Metric | ID | Target | Measurement Method |
|--------|-----|--------|--------------------|
| PII detection recall (text, high-confidence entities) | M-01 | > 95% for DNI/NIE/IBAN/email | Test suite with known PII documents |
| PII detection recall (text, NER-based entities) | M-02 | > 70% for person names | Manual evaluation on diverse Spanish documents |
| PII detection recall (visual, faces) | M-03 | > 85% | Test suite with portrait photos at various sizes |
| Processing time (10-page native PDF) | M-04 | < 5 seconds | Automated benchmarks on reference hardware |
| False positive rate (all entities) | M-05 | < 10% | Manual evaluation on clean documents |
| API availability | M-06 | 99.9% (production target) | Uptime monitoring |
| Redaction completeness | M-07 | 100% of detected entities are redacted | Post-sanitization text extraction verification |
| Output file validity | M-08 | 100% of outputs are valid files | Automated validation (PDF parser, image decoder) |

---

## 16. Open Questions

| ID | Question | Impact | Suggested Resolution |
|----|----------|--------|---------------------|
| Q-01 | Multi-language support priority? Which languages after Spanish? | Defines Phase 6 scope | English first (largest market), then French, German, Portuguese |
| Q-02 | Should we support real-time streaming sanitization? | API design, architecture | Not for MVP; consider WebSocket for progress reporting in Phase 5 |
| Q-03 | HIPAA vs GDPR first for compliance presets? | Phase 6 prioritization | GDPR first (European market focus), HIPAA second |
| Q-04 | Cloud vs on-premise as default deployment model? | Business model, pricing | Self-hosted first (privacy-conscious users), SaaS as optional tier |
| Q-05 | Pricing model for SaaS tier? | Revenue, positioning | Freemium: free tier (N docs/month), paid by volume. Enterprise: flat rate |
| Q-06 | Should the YuNet model be bundled in the repo or downloaded at build time? | Docker build reproducibility | Download at build time (current approach) — smaller repo, always latest model |
| Q-07 | Optimal confidence thresholds per entity type? | Detection accuracy tradeoff | Start with defaults (0.7 regex, 0.5 NER), tune based on real-world evaluation |
| Q-08 | Should we cache OCR results per page within a request? | Performance for multi-page scanned PDFs | Yes — OCR is expensive, cache TextPage objects during extraction |

---

## 17. Competitive Landscape

| Solution | Type | PII Detection | Document Sanitization | Self-Hosted | Real Redaction | AI-Native | Price |
|----------|------|--------------|----------------------|-------------|---------------|-----------|-------|
| **Saniflow** | Open-source platform | Text + visual | PDF + images | Yes | Yes (content removal) | MCP roadmap | Free |
| AWS Comprehend | Cloud API | Text only | No (detection only) | No | N/A | No | Pay-per-use |
| Google Cloud DLP | Cloud API | Text only | Partial (masking) | No | No (masking only) | No | Pay-per-use |
| Microsoft Presidio | Open-source library | Text only | No (library only) | Yes (lib) | N/A | No | Free |
| Private AI | Commercial SaaS | Text + some visual | Yes | Cloud or on-prem | Yes | No | Enterprise |
| Adobe Acrobat | Desktop software | No (manual only) | Yes (manual) | Yes (desktop) | Yes | No | Subscription |
| DocuSign CLM | Enterprise SaaS | Limited | Limited | No | No | No | Enterprise |

**Saniflow's positioning:**
- **vs AWS/Google**: Self-hosted (data never leaves your infrastructure), performs actual document sanitization (not just detection), and is free and open source.
- **vs Presidio**: Builds ON Presidio but provides a complete platform — API, visual detection, document redaction, Docker deployment. Presidio is a library; Saniflow is a product.
- **vs Private AI**: Open-source, free, and fully self-hosted. No vendor lock-in, no licensing fees.
- **vs Manual tools**: Automated, API-first, and scales to AI pipelines. Manual redaction does not scale.
- **Unique differentiator**: MCP-native AI integration. No competitor offers an MCP server for AI tool sanitization. Saniflow is designed for the AI era from day one.

---

*This document is the single source of truth for the Saniflow project. All design decisions, technical specifications, and roadmap items are tracked here. Last updated: 2026-03-23.*
