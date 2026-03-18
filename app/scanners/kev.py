"""CISA KEV catalog - flags findings in Known Exploited Vulnerabilities."""

import httpx

from app.core.config import get_settings
from app.core.logging_config import get_logger
from app.schemas.scan import VulnerabilityItem

logger = get_logger(__name__)

_kev_cache: set[str] | None = None


def _load_kev_catalog() -> set[str]:
    """Load CISA KEV catalog and return set of CVE IDs. Cached in memory."""
    global _kev_cache
    if _kev_cache is not None:
        return _kev_cache

    settings = get_settings()
    try:
        with httpx.Client(timeout=settings.kev_timeout) as client:
            resp = client.get(settings.kev_catalog_url)
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, httpx.TimeoutException) as e:
        logger.warning("KEV catalog fetch failed: %s", e)
        _kev_cache = set()
        return _kev_cache

    vulns = data.get("vulnerabilities", [])
    cve_ids = {v.get("cveID", "").upper() for v in vulns if v.get("cveID")}
    _kev_cache = cve_ids
    logger.info("Loaded %d CVE IDs from CISA KEV catalog", len(cve_ids))
    return cve_ids


def is_kev_listed(vulnerability_id: str, aliases: list[str] | None = None) -> bool:
    """Check if CVE is in CISA KEV catalog."""
    kev = _load_kev_catalog()
    if not kev:
        return False
    vid_upper = vulnerability_id.upper()
    if vid_upper in kev:
        return True
    for a in aliases or []:
        if a.upper() in kev:
            return True
    return False


def apply_kev_flags(items: list[VulnerabilityItem]) -> list[VulnerabilityItem]:
    """Set kev_listed on each item. Returns new list."""
    kev = _load_kev_catalog()
    if not kev:
        return items

    result: list[VulnerabilityItem] = []
    for item in items:
        listed = item.vulnerability_id.upper() in kev or any(
            a.upper() in kev for a in (item.aliases or [])
        )
        result.append(
            VulnerabilityItem(
                package=item.package,
                current_version=item.current_version,
                vulnerability_id=item.vulnerability_id,
                summary=item.summary,
                fixed_versions=item.fixed_versions,
                source=item.source,
                severity=item.severity,
                kev_listed=listed,
                priority=item.priority,
                priority_rationale=item.priority_rationale,
                aliases=item.aliases,
                osv_enriched=item.osv_enriched,
            )
        )
    return result


def clear_kev_cache() -> None:
    """Clear KEV cache (for tests)."""
    global _kev_cache
    _kev_cache = None
