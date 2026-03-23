import json
import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from app.api.routes import router
from app.api.schemas import ErrorResponse, HealthResponse
from app.config import settings

logger = logging.getLogger(__name__)


# ── Structured JSON log formatter ─────────────────────────────────────


class JsonFormatter(logging.Formatter):
    """Emit each log record as a single JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        entry: dict = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Merge extra fields injected via ``extra={...}``
        for key in ("method", "path", "status", "duration_ms", "client_ip"):
            value = getattr(record, key, None)
            if value is not None:
                entry[key] = value
        return json.dumps(entry, default=str)


def _configure_logging() -> None:
    """Set up root logger based on SANIFLOW_LOG_LEVEL / SANIFLOW_LOG_FORMAT."""
    root = logging.getLogger()
    root.setLevel(getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO))

    handler = logging.StreamHandler()
    if settings.LOG_FORMAT == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-8s [%(name)s] %(message)s")
        )

    root.handlers = [handler]


# ── Application lifespan ──────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: setup and teardown."""
    _configure_logging()

    temp_dir = Path(settings.TEMP_DIR)
    temp_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Created temp directory: %s", temp_dir)

    # Configure dedicated audit logger (JSON Lines → file, no propagation)
    if settings.AUDIT_ENABLED:
        audit_logger = logging.getLogger("saniflow.audit")
        audit_logger.setLevel(logging.INFO)
        audit_logger.propagate = False
        audit_handler = logging.FileHandler(settings.AUDIT_LOG_PATH)
        audit_handler.setFormatter(logging.Formatter("%(message)s"))
        audit_logger.addHandler(audit_handler)
        logger.info("Audit logging enabled → %s", settings.AUDIT_LOG_PATH)

    yield
    logger.info("Shutting down Saniflow")


tags_metadata = [
    {
        "name": "Sanitization",
        "description": (
            "Upload documents (PDF, JPEG, PNG) to detect and redact personally "
            "identifiable information (PII). Supports configurable sanitization "
            "levels, redaction styles, and selective entity targeting."
        ),
    },
    {
        "name": "Health",
        "description": "Operational health and readiness checks.",
    },
]

app = FastAPI(
    title="Saniflow API",
    version="0.1.0",
    description=(
        "**Saniflow** is a document sanitization pipeline that automatically detects "
        "and redacts personally identifiable information (PII) from documents and images.\n\n"
        "### Key Features\n\n"
        "- **Multi-format support** — PDF, JPEG, and PNG files\n"
        "- **PII detection** — Names, DNI/NIE, emails, phone numbers, IBANs, "
        "addresses, dates of birth, faces, and signatures\n"
        "- **Configurable redaction** — Black-box, blur, or placeholder replacement\n"
        "- **Flexible output** — Download the sanitized file, get a JSON findings report, "
        "or both\n"
        "- **Selective redaction** — Choose which entity types to redact\n"
        "- **Sanitization levels** — `standard` or `strict` for different privacy requirements\n\n"
        "### Authentication\n\n"
        "All endpoints require an API key passed via the `X-API-Key` header.\n\n"
        "### Rate Limiting\n\n"
        "Responses include `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and "
        "`X-RateLimit-Reset` headers."
    ),
    openapi_tags=tags_metadata,
    lifespan=lifespan,
)

class RateLimitHeadersMiddleware(BaseHTTPMiddleware):
    """Inject X-RateLimit-* headers from request.state into responses."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        if hasattr(request.state, "rate_limit_limit"):
            response.headers["X-RateLimit-Limit"] = str(request.state.rate_limit_limit)
            response.headers["X-RateLimit-Remaining"] = str(request.state.rate_limit_remaining)
            response.headers["X-RateLimit-Reset"] = str(request.state.rate_limit_reset)
        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log every HTTP request with method, path, status, duration, and client IP."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        start = time.monotonic()
        response = await call_next(request)
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.info(
            "%s %s %s %dms",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
            extra={
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": duration_ms,
                "client_ip": request.client.host if request.client else None,
            },
        )
        return response


app.add_middleware(RateLimitHeadersMiddleware)
app.add_middleware(RequestLoggingMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all for unhandled exceptions — never leak internal details."""
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal processing error"},
    )


@app.get(
    "/api/v1/health",
    response_model=HealthResponse,
    tags=["Health"],
    summary="Check service health",
    response_description="Service status and version information.",
    responses={
        500: {"model": ErrorResponse, "description": "Internal processing error"},
    },
)
async def health_check() -> HealthResponse:
    """Return the current health status and version of the Saniflow service.

    This endpoint does not require authentication and can be used by load
    balancers or orchestrators for liveness and readiness probes.
    """
    return HealthResponse(status="healthy", version="0.1.0")
