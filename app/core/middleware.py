"""Request ID and timing middleware."""

import time
import uuid
from collections.abc import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.logging_config import get_logger

logger = get_logger(__name__)


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Adds X-Request-ID header, request timing, and structured request logging."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id
        start = time.perf_counter()
        response = await call_next(request)
        duration = time.perf_counter() - start
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time-Ms"] = f"{duration * 1000:.2f}"
        request.state.duration = duration

        logger.info(
            "Request completed",
            extra={
                "request_id": request_id,
                "endpoint": str(request.url.path),
                "duration": round(duration, 4),
                "status": response.status_code,
            },
        )
        return response
