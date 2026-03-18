"""TaskForge Security - DevSecOps security service."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.api.routes import gate, health, info, metrics, remediation, scan
from app.core.config import get_settings
from app.core.logging_config import setup_logging
from app.core.middleware import RequestIDMiddleware
from app.core.rate_limit import limiter


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle."""
    settings = get_settings()
    setup_logging(settings.log_level)
    if settings.is_production and not settings.require_api_key:
        import logging
        logging.getLogger("app").warning(
            "APP_ENV=production but REQUIRE_API_KEY=false. "
            "Set REQUIRE_API_KEY=true and API_KEY for production deployments."
        )
    yield


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    app = FastAPI(
        title="TaskForge Security",
        description="Platform security - CVE scanning, OSV/KEV enrichment, remediation planning",
        version="0.2.0",
        lifespan=lifespan,
    )

    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(RequestIDMiddleware)

    app.include_router(health.router)
    app.include_router(metrics.router)
    app.include_router(info.router, prefix="/api/v1")
    app.include_router(scan.router, prefix="/api/v1")
    app.include_router(gate.router, prefix="/api/v1")
    app.include_router(remediation.router, prefix="/api/v1")

    return app


app = create_app()
