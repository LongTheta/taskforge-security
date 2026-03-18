"""TaskForge Security - DevSecOps security service."""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.routes import health, remediation, scan
from app.core.config import get_settings
from app.core.logging_config import setup_logging
from app.core.middleware import RequestIDMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle."""
    settings = get_settings()
    setup_logging(settings.log_level)
    yield
    # Shutdown if needed


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    app = FastAPI(
        title="TaskForge Security",
        description="DevSecOps security service - CVE scanning, remediation, GitOps integration",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.add_middleware(RequestIDMiddleware)

    app.include_router(health.router, prefix="/api/v1")
    app.include_router(scan.router, prefix="/api/v1")
    app.include_router(remediation.router, prefix="/api/v1")

    return app


app = create_app()
