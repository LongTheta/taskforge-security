"""Scan service - orchestrates pip-audit and returns normalized results."""

from app.core.config import get_settings
from app.core.logging_config import get_logger
from app.scanners import pip_audit, requirements
from app.schemas.scan import ScanResponse, VulnerabilityItem

logger = get_logger(__name__)


def run_scan(
    target_path: str,
    manifest_path: str = "requirements.txt",
) -> ScanResponse:
    """
    Run vulnerability scan via pip-audit.
    Validates paths, prevents traversal, returns deduplicated results.
    """
    settings = get_settings()
    target = requirements.validate_target_path(target_path)
    manifest = requirements.resolve_manifest_path(target_path, manifest_path)

    if not manifest.exists():
        raise FileNotFoundError(f"manifest file not found: {manifest}")

    logger.info(
        "Starting scan",
        extra={"target_path": str(target), "manifest_path": str(manifest)},
    )

    items = pip_audit.run_pip_audit(manifest, settings.scan_timeout)
    deduped = _deduplicate(items)

    return ScanResponse(
        vulnerability_count=len(deduped),
        vulnerabilities=deduped,
    )


def _deduplicate(items: list[VulnerabilityItem]) -> list[VulnerabilityItem]:
    """Deduplicate by (package, vulnerability_id)."""
    seen: set[tuple[str, str]] = set()
    result: list[VulnerabilityItem] = []
    for item in items:
        key = (item.package, item.vulnerability_id)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result
