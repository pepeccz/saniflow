"""API key authentication dependency for FastAPI."""

from __future__ import annotations

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

from app.config import settings

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def require_api_key(
    api_key: str | None = Security(_api_key_header),
) -> str | None:
    """Validate the X-API-Key header when authentication is enabled.

    If ``settings.API_KEYS`` is empty, authentication is disabled (dev mode)
    and the dependency is a no-op.  When enabled, an invalid or missing key
    returns **401 Unauthorized**.
    """
    if not settings.API_KEYS:
        # Auth disabled — open access.
        return None

    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key. Provide a valid X-API-Key header.",
        )

    if api_key not in settings.API_KEYS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
        )

    return api_key
