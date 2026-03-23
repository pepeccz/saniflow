<div align="center">

<pre>
                    ____              _  __ _
                   / ___|  __ _ _ __ (_)/ _| | _____      __
                   \___ \ / _` | '_ \| | |_| |/ _ \ \ /\ / /
                    ___) | (_| | | | | |  _| | (_) \ V  V /
                   |____/ \__,_|_| |_|_|_| |_|\___/ \_/\_/

              +------------------------------------------+
              |  DOCUMENT IN         CLEAN DOCUMENT OUT  |
              |                                          |
              |   [PII]  ------>  [ -------- ]  -------> |
              |   Names             [REDACTED]       AI  |
              |   DNIs              [REDACTED]           |
              |   IBANs             [REDACTED]           |
              |   Faces             [BLOCKED]            |
              |                                          |
              +------------------------------------------+
</pre>

<h1>Saniflow</h1>

<p><strong>The sanitization layer between your documents and AI — detect, redact, forget.</strong></p>

<p>
  <a href="https://github.com/Memory-Bank/saniflow/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/python-3.12+-3776AB.svg?logo=python&logoColor=white" alt="Python 3.12+">
  <img src="https://img.shields.io/badge/FastAPI-009688.svg?logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/Docker-2496ED.svg?logo=docker&logoColor=white" alt="Docker">
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS-lightgrey" alt="Platform">
</p>

</div>

---

## What It Does

Saniflow is a stateless document sanitization API. It sits between your application and any AI model, ensuring no personally identifiable information ever leaves your perimeter.

Upload a PDF or image. Saniflow extracts text and visual content, detects PII using NLP and pattern matching, applies real redaction (not visual overlays), and returns a clean document.

```
Without Saniflow                          With Saniflow

  contract.pdf -----> AI Model              contract.pdf -----> Saniflow -----> AI Model
  (names, DNIs,       (PII exposed,           |                                   |
   IBANs, faces)       compliance risk)        v                                   v
                                          detect + redact                    zero PII exposure
                                          12 entities found                  compliance maintained
```

---

## Quick Start

```bash
cp .env.example .env
docker compose up --build
```

The API is available at `http://localhost:8000`.

```bash
# Optional: enable API key auth for production
echo "SANIFLOW_API_KEYS=your-key-here" >> .env
```

**Sanitize a file (get sanitized document back):**

```bash
curl -X POST http://localhost:8000/api/v1/sanitize \
  -F "file=@document.pdf" \
  -F "level=standard" \
  -F "response_format=file" \
  -o document_sanitized.pdf
```

**Get findings as JSON:**

```bash
curl -X POST http://localhost:8000/api/v1/sanitize \
  -F "file=@document.pdf" \
  -F "level=strict" \
  -F "response_format=json"
```

**Get both (file as base64 + findings):**

```bash
curl -X POST http://localhost:8000/api/v1/sanitize \
  -F "file=@photo.jpg" \
  -F "level=strict" \
  -F "response_format=full"
```

---

## Features

- **File types** -- PDF, JPEG, PNG
- **Text PII detection** -- Person names, DNI/NIE, email, phone, IBAN, addresses
- **Visual PII detection** -- Faces (YuNet/OpenCV), signatures (strict mode)
- **Two sanitization levels** -- `standard` (text PII) and `strict` (text + visual)
- **Three response formats** -- Sanitized file, JSON findings report, or both
- **Real redaction** -- Underlying content is removed from PDFs via PyMuPDF, not just covered with rectangles
- **Stateless** -- No database, no sessions. Process and forget.
- **Spanish-focused** -- Built with Spanish NER models and document patterns (spaCy + Presidio)
- **API key authentication** -- Optional `X-API-Key` header auth via `SANIFLOW_API_KEYS` env var
- **Rate limiting** -- Per-IP sliding window rate limiter (configurable, default 30 req/min)
- **MCP Server** -- AI-native integration via Model Context Protocol (stdio transport)
- **Image preprocessing** -- EXIF auto-rotation, document region extraction, OCR enhancement
- **Async processing** -- Non-blocking pipeline execution via thread pool

---

## API Reference

### `POST /api/v1/sanitize`

| Parameter         | Type   | Default    | Description                                |
|-------------------|--------|------------|--------------------------------------------|
| `file`            | file   | (required) | PDF, JPEG, or PNG to sanitize              |
| `level`           | string | `standard` | Sanitization level: `standard` or `strict` |
| `response_format` | string | `file`     | Response format: `file`, `json`, or `full` |

**Response formats:**

| Format | Returns |
|--------|---------|
| `file` | Sanitized file as binary download (no additional headers) |
| `json` | JSON object with findings and summary |
| `full` | JSON object with findings, summary, and the sanitized file as base64 |

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

**Error responses:**

| Status | Condition                             |
|--------|---------------------------------------|
| 401    | Invalid or missing API key (when auth is enabled) |
| 413    | File exceeds max size (default 20 MB)              |
| 415    | Unsupported file type                              |
| 422    | Invalid level/format or corrupted file             |
| 429    | Rate limit exceeded                                |
| 500    | Internal processing error                          |

### `GET /api/v1/health`

```json
{"status": "healthy", "version": "0.1.0"}
```

---

## MCP Server

Saniflow exposes an MCP (Model Context Protocol) server for AI agent integration using stdio transport. It provides three tools:

| Tool | Description |
|------|-------------|
| `sanitize_file` | Sanitize a local file by path |
| `sanitize_base64` | Sanitize base64-encoded content |
| `check_pii` | Inspect a file for PII without applying redactions |

**Configure in Claude Code settings:**

```json
{
  "mcpServers": {
    "saniflow": {
      "command": "python",
      "args": ["-m", "app.mcp_server"],
      "cwd": "/path/to/saniflow"
    }
  }
}
```

**Or via Docker:**

```json
{
  "mcpServers": {
    "saniflow": {
      "command": "docker",
      "args": ["compose", "run", "--rm", "-i", "saniflow-mcp"]
    }
  }
}
```

---

## Sanitization Levels

| Level      | Text PII | Faces | Signatures |
|------------|----------|-------|------------|
| `standard` | Yes      | No    | No         |
| `strict`   | Yes      | Yes   | Yes        |

---

## Entity Types

| Entity Type   | Detection Method        | Level    |
|---------------|-------------------------|----------|
| `PERSON_NAME` | spaCy NER               | standard |
| `DNI_NIE`     | Regex pattern           | standard |
| `EMAIL`       | Regex + Presidio        | standard |
| `PHONE`       | Regex + Presidio        | standard |
| `IBAN`        | Regex pattern           | standard |
| `ADDRESS`     | spaCy NER               | standard |
| `FACE`        | YuNet (OpenCV)          | strict   |
| `SIGNATURE`   | OpenCV contour analysis | strict   |

---

## Configuration

All environment variables are prefixed with `SANIFLOW_`. Copy `.env.example` to `.env` to get started.

| Variable                              | Default                                        | Description                          |
|---------------------------------------|------------------------------------------------|--------------------------------------|
| `SANIFLOW_MAX_FILE_SIZE`              | `20971520` (20 MB)                             | Maximum upload file size in bytes    |
| `SANIFLOW_SUPPORTED_FORMATS`          | `["application/pdf","image/jpeg","image/png"]`  | Accepted MIME types                  |
| `SANIFLOW_DEFAULT_LEVEL`              | `standard`                                     | Default sanitization level           |
| `SANIFLOW_CONFIDENCE_THRESHOLD_REGEX` | `0.7`                                          | Minimum confidence for regex matches |
| `SANIFLOW_CONFIDENCE_THRESHOLD_NER`   | `0.5`                                          | Minimum confidence for NER matches   |
| `SANIFLOW_TESSERACT_LANG`            | `spa`                                          | Tesseract OCR language               |
| `SANIFLOW_SPACY_MODEL`               | `es_core_news_md`                              | spaCy model for NER                  |
| `SANIFLOW_YUNET_MODEL_PATH`          | `/app/models/face_detection_yunet_2023mar.onnx` | Path to YuNet face detection model   |
| `SANIFLOW_YUNET_SCORE_THRESHOLD`     | `0.4`                                          | Minimum confidence for face detection |
| `SANIFLOW_API_KEYS`                  | (empty = disabled)                             | Comma-separated list of valid API keys |
| `SANIFLOW_RATE_LIMIT`               | `30`                                           | Max requests per minute per client IP |
| `SANIFLOW_DOCUMENT_EXTRACTION_ENABLED` | `true`                                       | Enable document region extraction from images |
| `SANIFLOW_DOCUMENT_MIN_AREA_RATIO`  | `0.10`                                         | Minimum area ratio for document extraction (10%) |
| `SANIFLOW_TEMP_DIR`                  | `/tmp/saniflow`                                | Temporary file directory             |

---

## Development

### Run locally (without Docker)

Requires Python 3.12+, Tesseract OCR with Spanish language pack, and the YuNet ONNX model.

```bash
pip install -e ".[dev]"

python -m spacy download es_core_news_md

mkdir -p models
curl -L -o models/face_detection_yunet_2023mar.onnx \
  https://github.com/opencv/opencv_zoo/raw/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx

export SANIFLOW_YUNET_MODEL_PATH=models/face_detection_yunet_2023mar.onnx

uvicorn app.main:app --reload
```

### Run tests

```bash
pytest
pytest -m "not slow"         # skip slow tests
pytest -m "not integration"  # unit tests only
```

---

## Architecture

The core is a **pipeline pattern** with pluggable stages:

```
Request --> Orchestrator --> Extractor --> Detector --> Sanitizer --> Response
                |               |             |             |
                |          PyMuPDF        Presidio      PyMuPDF
                |          Pillow         spaCy         Pillow
                |          Tesseract      OpenCV
                |
           Resolves file type,
           selects the right chain
```

- **Orchestrator** -- Resolves file type, selects the right chain of extractor, detector, and sanitizer
- **Extractors** -- Pull text blocks and embedded images from PDFs and images
- **Detectors** -- Run Presidio (text PII) and OpenCV (visual PII) based on sanitization level
- **Sanitizers** -- Apply real redactions on the original file using coordinates from detectors

Each stage uses abstract base classes with concrete implementations per file type, making it straightforward to add new formats.

---

## Tech Stack

- **Python 3.12** / **FastAPI** / **Uvicorn**
- **Presidio** + **spaCy** -- text PII detection and NER
- **PyMuPDF** -- PDF extraction and redaction
- **Tesseract OCR** -- text extraction from images
- **OpenCV** -- face and signature detection
- **Pillow** -- image processing
- **Docker** -- containerization

---

<div align="center">

<a href="https://github.com/Memory-Bank/saniflow/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>

<p><sub>MIT License -- Copyright (c) 2025 Pepe Cabeza Cruz</sub></p>

</div>
