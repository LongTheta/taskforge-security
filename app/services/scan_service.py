"""Scan service - orchestrates scanners and returns normalized results."""

from app.core.config import get_settings
from app.core.logging_config import get_logger
from app.schemas.scan import ScanResponse
from app.scanners import osv, pip_audit, requirements

logger = get_logger(__name__)


def run_scan(  # noqa: PLR0913
    target_path: str,
    manifest_path: str = "requirements.txt",
    include_osv_enrichment: bool = False,
) -> ScanResponse:
    """
    Run vulnerability scan: pip-audit + optional OSV enrichment.
    Validates paths, limits scope to local directory.
    """
    settings = get_settings()
    target = requirements.validate_target_path(target_path)
    manifest = requirements.resolve_manifest_path(target_path, manifest_path)

    if not manifest.exists():
        raise FileNotFoundError(f"manifest file not found: {manifest}")

    logger.info(
        "Starting scan",
        extra={
            "target_path": str(target),
            "manifest_path": str(manifest),
            "include_osv_enrichment": include_osv_enrichment,
        },
    )

    items = pip_audit.run_pip_audit(manifest, settings.scan_timeout)

    if include_osv_enrichment and items:
        items = osv.enrich_with_osv(
            items,
            api_base=settings.osv_api_base,
            timeout=min(30, settings.scan_timeout),
        )

    return ScanResponse(
        total_vulnerabilities=len(items),
        vulnerabilities=items,
    )
