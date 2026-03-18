"""Info endpoint - build/version metadata."""

from fastapi import APIRouter

from app.integrations.github.pr_creator import validate_github_config
from app.scanners.trivy import trivy_available

router = APIRouter(prefix="/info", tags=["info"])


@router.get("")
def info() -> dict:
    """GET /api/v1/info - service metadata."""
    github_ok, _ = validate_github_config()
    return {
        "service": "taskforge-security",
        "version": "0.2.0",
        "description": "DevSecOps security service - CVE scanning, remediation planning, OSV/KEV enrichment",
        "capabilities": {
            "trivy_image_scan": trivy_available(),
            "github_pr_creation": github_ok,
        },
        "endpoints": {
            "health": "/health",
            "scan": "/api/v1/scan",
            "scan_image": "/api/v1/scan/image",
            "gate": "/api/v1/gate",
            "remediate": "/api/v1/remediate",
            "create_pr": "/api/v1/remediate/create-pr",
            "preview_pr": "/api/v1/remediate/preview-pr",
            "info": "/api/v1/info",
        },
    }
