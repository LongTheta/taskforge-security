"""Scan service - orchestrates pip-audit, Trivy, OSV, KEV, and returns normalized results."""

from app.core.config import get_settings
from app.core.logging_config import get_logger
from app.scanners import kev, osv, pip_audit, requirements, trivy
from app.schemas.scan import RiskSummary, ScanResponse, VulnerabilityItem
from app.services.priority import apply_priorities

logger = get_logger(__name__)


def run_scan(
    target_path: str,
    manifest_path: str = "requirements.txt",
    include_osv_enrichment: bool = True,
    include_kev_prioritization: bool = True,
) -> ScanResponse:
    """
    Run vulnerability scan via pip-audit.
    Optionally enrich with OSV and flag KEV-listed findings.
    Validates paths, prevents traversal, returns deduplicated results.
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
            "include_kev_prioritization": include_kev_prioritization,
        },
    )

    items = pip_audit.run_pip_audit(manifest, settings.scan_timeout)
    deduped = _deduplicate(items)

    osv_available = False
    if include_osv_enrichment and deduped:
        try:
            deduped = osv.enrich_with_osv(
                deduped,
                api_base=settings.osv_api_base,
                timeout=min(settings.osv_timeout, settings.scan_timeout),
            )
            osv_available = any(i.osv_enriched for i in deduped)
        except Exception as e:
            logger.warning("OSV enrichment failed: %s", e)

    kev_available = False
    if include_kev_prioritization and deduped:
        try:
            deduped = kev.apply_kev_flags(deduped)
            kev_available = any(i.kev_listed for i in deduped)
        except Exception as e:
            logger.warning("KEV prioritization failed: %s", e)

    deduped = apply_priorities(deduped)
    risk_summary = _compute_risk_summary(deduped)

    return ScanResponse(
        vulnerability_count=len(deduped),
        vulnerabilities=deduped,
        risk_summary=risk_summary,
        osv_enrichment_available=osv_available,
        kev_prioritization_available=kev_available,
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


def _compute_risk_summary(items: list[VulnerabilityItem]) -> RiskSummary:
    """Compute risk summary from prioritized items."""
    critical = high = medium = low = kev_count = 0
    for item in items:
        if item.kev_listed:
            kev_count += 1
        p = (item.priority or "").lower()
        if p == "critical":
            critical += 1
        elif p == "high":
            high += 1
        elif p == "medium":
            medium += 1
        else:
            low += 1
    return RiskSummary(
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low,
        kev_count=kev_count,
    )


def run_image_scan(
    image_ref: str,
    include_kev_prioritization: bool = True,
) -> ScanResponse:
    """
    Run Trivy vulnerability scan on container image.
    Requires trivy CLI. Optionally flags KEV-listed findings.
    """
    settings = get_settings()
    items = trivy.run_trivy_image(image_ref, timeout=settings.scan_timeout)
    deduped = _deduplicate(items)

    kev_available = False
    if include_kev_prioritization and deduped:
        try:
            deduped = kev.apply_kev_flags(deduped)
            kev_available = any(i.kev_listed for i in deduped)
        except Exception as e:
            logger.warning("KEV prioritization failed: %s", e)

    deduped = apply_priorities(deduped)
    risk_summary = _compute_risk_summary(deduped)

    return ScanResponse(
        vulnerability_count=len(deduped),
        vulnerabilities=deduped,
        risk_summary=risk_summary,
        osv_enrichment_available=False,
        kev_prioritization_available=kev_available,
    )
