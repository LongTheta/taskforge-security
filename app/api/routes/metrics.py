"""Prometheus metrics endpoint."""

from fastapi import APIRouter, Response

from app.core.metrics import get_metrics

router = APIRouter(tags=["metrics"])


@router.get("/metrics")
def metrics() -> Response:
    """GET /metrics - Prometheus exposition format."""
    return Response(
        content=get_metrics(),
        media_type="text/plain; charset=utf-8",
    )
