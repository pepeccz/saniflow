import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from app.api.routes import router
from app.api.schemas import HealthResponse
from app.config import settings

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: setup and teardown."""
    temp_dir = Path(settings.TEMP_DIR)
    temp_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Created temp directory: %s", temp_dir)
    yield
    logger.info("Shutting down Saniflow")


app = FastAPI(
    title="Saniflow",
    version="0.1.0",
    description="Sanitization pipeline for PII detection and redaction in documents and images",
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


app.add_middleware(RateLimitHeadersMiddleware)

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


@app.get("/api/v1/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Health check endpoint."""
    return HealthResponse(status="healthy", version="0.1.0")
