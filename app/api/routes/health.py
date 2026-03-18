"""Health check endpoint."""

from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict:
    """Liveness/readiness probe."""
    return {"status": "ok", "service": "taskforge-security"}
