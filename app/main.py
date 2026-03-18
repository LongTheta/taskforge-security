"""TaskForge Security - DevSecOps security service."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.api.routes import health, scan
from app.core.config import get_settings
from app.core.logging_config import setup_logging
from app.core.middleware import RequestIDMiddleware
from app.core.rate_limit import limiter


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle."""
    settings = get_settings()
    setup_logging(settings.log_level)
    yield


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    app = FastAPI(
        title="TaskForge Security",
        description="DevSecOps security service - CVE scanning via pip-audit",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(RequestIDMiddleware)

    app.include_router(health.router)
    app.include_router(scan.router, prefix="/api/v1")

    return app


app = create_app()
