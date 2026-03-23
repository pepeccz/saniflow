"""Simple in-memory sliding-window rate limiter for FastAPI."""

from __future__ import annotations

import threading
import time

from fastapi import HTTPException, Request

from app.config import settings

# Module-level store: IP -> list of request timestamps
_request_store: dict[str, list[float]] = {}
_lock = threading.Lock()

# Window size in seconds
_WINDOW: int = 60


def _cleanup(timestamps: list[float], now: float) -> list[float]:
    """Remove timestamps older than the sliding window."""
    cutoff = now - _WINDOW
    return [t for t in timestamps if t > cutoff]


async def check_rate_limit(request: Request) -> None:
    """FastAPI dependency that enforces per-IP rate limiting.

    Raises 429 Too Many Requests with a Retry-After header when the
    client exceeds ``settings.RATE_LIMIT`` requests per minute.

    Adds X-RateLimit-* headers to the response via ``request.state``.
    """
    limit = settings.RATE_LIMIT
    if limit <= 0:
        # Rate limiting disabled
        return

    client_ip = request.client.host if request.client else "unknown"
    now = time.time()

    with _lock:
        timestamps = _request_store.get(client_ip, [])
        timestamps = _cleanup(timestamps, now)

        if len(timestamps) >= limit:
            # Calculate when the oldest request in the window expires
            retry_after = int(timestamps[0] + _WINDOW - now) + 1
            _request_store[client_ip] = timestamps
            raise HTTPException(
                status_code=429,
                detail="Too many requests",
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(timestamps[0] + _WINDOW)),
                },
            )

        timestamps.append(now)
        _request_store[client_ip] = timestamps
        remaining = limit - len(timestamps)

    # Store rate limit info for response headers
    request.state.rate_limit_limit = limit
    request.state.rate_limit_remaining = remaining
    request.state.rate_limit_reset = int(now + _WINDOW)


def reset_store() -> None:
    """Clear the rate limit store. Useful for testing."""
    with _lock:
        _request_store.clear()
