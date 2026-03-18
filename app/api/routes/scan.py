"""Scan endpoint."""

from fastapi import APIRouter, HTTPException, Request

from app.core.logging_config import get_logger
from app.schemas.scan import ScanRequest, ScanResponse
from app.services.scan_service import run_scan

router = APIRouter(prefix="/scan", tags=["scan"])
logger = get_logger(__name__)


@router.post("", response_model=ScanResponse)
def post_scan(request: Request, body: ScanRequest) -> ScanResponse:
    """
    POST /api/v1/scan
    Run vulnerability scan against target path and manifest.
    """
    request_id = getattr(request.state, "request_id", "unknown")
    extra = {
        "request_id": request_id,
        "endpoint": "/api/v1/scan",
        "target_path": body.target_path,
        "manifest_path": body.manifest_path,
    }

    try:
        return run_scan(
            target_path=body.target_path,
            manifest_path=body.manifest_path,
            include_osv_enrichment=body.include_osv_enrichment,
        )
    except FileNotFoundError as e:
        logger.warning("Scan failed: file not found", extra={**extra, "error": str(e)})
        raise HTTPException(status_code=404, detail=str(e)) from e
    except ValueError as e:
        logger.warning("Scan failed: validation error", extra={**extra, "error": str(e)})
        raise HTTPException(status_code=400, detail=str(e)) from e
    except (RuntimeError, TimeoutError) as e:
        logger.exception("Scan failed", extra=extra)
        raise HTTPException(
            status_code=500,
            detail="Scan failed. Check logs for details.",
        ) from e
