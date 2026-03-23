# Saniflow

Stateless document sanitization API. Upload a PDF or image, get PII detected and redacted.

## What It Does

Saniflow runs a pipeline that extracts text and images from documents, detects personally identifiable information (PII) using NLP and pattern matching, and returns a redacted copy with real content removal — not just visual overlays.

**Pipeline**: Upload → Extract → Detect → Sanitize → Output

## Features

- **File types**: PDF, JPEG, PNG
- **Text PII detection**: person names, DNI/NIE, email, phone, IBAN, addresses (Spanish-focused via Presidio + spaCy)
- **Visual PII detection**: faces (YuNet/OpenCV), signatures (strict mode only)
- **Two sanitization levels**: `standard` (text PII) and `strict` (text + visual)
- **Three response formats**: sanitized file, JSON findings report, or both
- **Real redaction**: underlying content is removed from PDFs via PyMuPDF, not just covered
- **Stateless**: no database, no sessions — process and forget

## Quick Start

```bash
cp .env.example .env
docker compose up --build
```

The API is available at `http://localhost:8000`.

### Sanitize a PDF (get sanitized file back)

```bash
curl -X POST http://localhost:8000/api/v1/sanitize \
  -F "file=@document.pdf" \
  -F "level=standard" \
  -F "response_format=file" \
  -o document_sanitized.pdf
```

### Get findings as JSON

```bash
curl -X POST http://localhost:8000/api/v1/sanitize \
  -F "file=@document.pdf" \
  -F "level=strict" \
  -F "response_format=json"
```

### Get both (file as base64 + findings)

```bash
curl -X POST http://localhost:8000/api/v1/sanitize \
  -F "file=@photo.jpg" \
  -F "level=strict" \
  -F "response_format=full"
```

### Health check

```bash
curl http://localhost:8000/api/v1/health
```

```json
{"status": "healthy", "version": "0.1.0"}
```

## API Reference

### `POST /api/v1/sanitize`

Sanitize a document by detecting and redacting PII.

**Parameters** (multipart form):

| Parameter         | Type   | Default    | Description                              |
|-------------------|--------|------------|------------------------------------------|
| `file`            | file   | (required) | PDF, JPEG, or PNG to sanitize            |
| `level`           | string | `standard` | Sanitization level: `standard` or `strict` |
| `response_format` | string | `file`     | Response format: `file`, `json`, or `full` |

**Response formats**:

- **`file`** — Returns the sanitized file as a binary download. Findings are included in the `X-Saniflow-Findings` response header as JSON.
- **`json`** — Returns findings and summary only (no file).
- **`full`** — Returns findings, summary, and the sanitized file as a base64-encoded string.

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
    }
  ],
  "summary": {
    "total_findings": 1,
    "by_type": {"PERSON_NAME": 1},
    "level_applied": "standard"
  },
  "file": "JVBERi0xLjQ..."
}
```

The `file` field is only present in `full` format. Fields `original_text`, `page`, and `bbox` may be `null` depending on the entity type.

**Error responses**:

| Status | Condition                          |
|--------|------------------------------------|
| 413    | File exceeds max size (default 20 MB) |
| 415    | Unsupported file type              |
| 422    | Invalid level/format or corrupted file |
| 500    | Internal processing error          |

### `GET /api/v1/health`

Returns service status.

```json
{"status": "healthy", "version": "0.1.0"}
```

## Sanitization Levels

| Level      | Text PII | Faces | Signatures |
|------------|----------|-------|------------|
| `standard` | Yes      | No    | No         |
| `strict`   | Yes      | Yes   | Yes        |

## Entity Types

| Entity Type   | Detection Method       | Level    |
|---------------|------------------------|----------|
| `PERSON_NAME` | spaCy NER              | standard |
| `DNI_NIE`     | Regex pattern          | standard |
| `EMAIL`       | Regex + Presidio       | standard |
| `PHONE`       | Regex + Presidio       | standard |
| `IBAN`        | Regex pattern          | standard |
| `ADDRESS`     | spaCy NER              | standard |
| `FACE`        | YuNet (OpenCV)         | strict   |
| `SIGNATURE`   | OpenCV contour analysis | strict   |

## Configuration

All environment variables are prefixed with `SANIFLOW_`. Copy `.env.example` to `.env` to get started.

| Variable                            | Default                                       | Description                        |
|-------------------------------------|-----------------------------------------------|------------------------------------|
| `SANIFLOW_MAX_FILE_SIZE`            | `20971520` (20 MB)                            | Maximum upload file size in bytes  |
| `SANIFLOW_SUPPORTED_FORMATS`        | `["application/pdf","image/jpeg","image/png"]` | Accepted MIME types                |
| `SANIFLOW_DEFAULT_LEVEL`            | `standard`                                    | Default sanitization level         |
| `SANIFLOW_CONFIDENCE_THRESHOLD_REGEX` | `0.7`                                       | Minimum confidence for regex matches |
| `SANIFLOW_CONFIDENCE_THRESHOLD_NER` | `0.5`                                         | Minimum confidence for NER matches |
| `SANIFLOW_TESSERACT_LANG`           | `spa`                                         | Tesseract OCR language             |
| `SANIFLOW_SPACY_MODEL`              | `es_core_news_md`                             | spaCy model for NER                |
| `SANIFLOW_YUNET_MODEL_PATH`         | `/app/models/face_detection_yunet_2023mar.onnx` | Path to YuNet face detection model |
| `SANIFLOW_TEMP_DIR`                 | `/tmp/saniflow`                               | Temporary file directory           |

## Development

### Run locally (without Docker)

Requires Python 3.12+, Tesseract OCR with Spanish language pack, and the YuNet ONNX model.

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

# Run
uvicorn app.main:app --reload
```

### Run tests

```bash
pytest
pytest -m "not slow"         # skip slow tests
pytest -m "not integration"  # unit tests only
```

## Architecture

The core is a **pipeline pattern** with pluggable stages:

```
Request → Orchestrator → Extractor → Detector → Sanitizer → Response
```

- **Orchestrator** (`app/pipeline/orchestrator.py`) — resolves file type, selects the right chain of extractor/detector/sanitizer
- **Extractors** (`app/pipeline/extractors/`) — pull text blocks and embedded images from PDFs and images (PyMuPDF, Pillow, Tesseract)
- **Detectors** (`app/pipeline/detectors/`) — run Presidio (text PII) and OpenCV (visual PII) based on the sanitization level
- **Sanitizers** (`app/pipeline/sanitizers/`) — apply real redactions on the original file using coordinates from detectors

Each stage uses base abstract classes with concrete implementations per file type, making it straightforward to add new formats.

## Roadmap

- Improved Spanish NER with larger spaCy models
- Async processing with background tasks for large files
- API key authentication
- Multi-tenant sanitization policies
- Audit trail and processing history
- MCP server for AI tool integration
- Web frontend

## Tech Stack

- **Python 3.12** / **FastAPI** / **Uvicorn**
- **Presidio** (text PII detection) + **spaCy** (NER)
- **PyMuPDF** (PDF extraction and redaction)
- **Tesseract OCR** (text from images)
- **OpenCV** (face and signature detection)
- **Pillow** (image processing)
- **Docker** (containerization)

## License

MIT
