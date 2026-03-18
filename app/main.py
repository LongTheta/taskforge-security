"""TaskForge Security - DevSecOps security service."""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.routes import health, scan
from app.core.config import get_settings
from app.core.logging_config import setup_logging
from app.core.middleware import RequestIDMiddleware


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

    app.add_middleware(RequestIDMiddleware)

    app.include_router(health.router)
    app.include_router(scan.router, prefix="/api/v1")

    return app


app = create_app()
