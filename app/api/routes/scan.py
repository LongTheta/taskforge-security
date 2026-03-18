"""Scan endpoint."""

from fastapi import APIRouter, Depends, HTTPException, Request

from app.core.auth import verify_api_key
from app.core.logging_config import get_logger
from app.core.metrics import scan_total, scan_vulnerabilities_total
from app.core.rate_limit import limiter
from app.schemas.scan import ScanImageRequest, ScanRequest, ScanResponse
from app.services.scan_service import run_image_scan, run_scan

router = APIRouter(prefix="/scan", tags=["scan"])
logger = get_logger(__name__)


@router.post("", response_model=ScanResponse)
@limiter.limit("10/minute")
def post_scan(
    request: Request,
    body: ScanRequest,
    _: None = Depends(verify_api_key),
) -> ScanResponse:
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
            include_kev_prioritization=body.include_kev_prioritization,
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


@router.post("/image", response_model=ScanResponse)
@limiter.limit("10/minute")
def post_scan_image(
    request: Request,
    body: ScanImageRequest,
    _: None = Depends(verify_api_key),
) -> ScanResponse:
    """
    POST /api/v1/scan/image
    Run Trivy vulnerability scan on container image. Requires trivy CLI.
    """
    request_id = getattr(request.state, "request_id", "unknown")
    extra = {
        "request_id": request_id,
        "endpoint": "/api/v1/scan/image",
        "image_ref": body.image_ref,
    }

    try:
        result = run_image_scan(
            image_ref=body.image_ref,
            include_kev_prioritization=body.include_kev_prioritization,
        )
        scan_total.labels(scan_type="image").inc()
        scan_vulnerabilities_total.inc(result.vulnerability_count)
        return result
    except ValueError as e:
        logger.warning("Image scan failed: validation error", extra={**extra, "error": str(e)})
        raise HTTPException(status_code=400, detail=str(e)) from e
    except (RuntimeError, TimeoutError) as e:
        logger.exception("Image scan failed", extra=extra)
        raise HTTPException(
            status_code=500,
            detail=str(e) if "not found" in str(e).lower() else "Image scan failed. Check logs.",
        ) from e
