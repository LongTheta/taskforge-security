"""OSV.dev enrichment - enriches pip-audit findings with OSV data."""

from app.core.logging_config import get_logger
from app.schemas.scan import VulnerabilityItem

logger = get_logger(__name__)


def enrich_with_osv(
    items: list[VulnerabilityItem],
    api_base: str,
    timeout: int,
) -> list[VulnerabilityItem]:
    """
    Enrich vulnerability items with OSV.dev API data.
    Fails gracefully if OSV is unavailable; returns original items.
    """
    if not items:
        return items

    try:
        import httpx
    except ImportError:
        logger.warning("httpx not installed; skipping OSV enrichment")
        return items

    # Build batch query for OSV
    queries = []
    for item in items:
        queries.append(
            {
                "package": {"name": item.package, "ecosystem": "PyPI"},
                "version": item.current_version,
            }
        )

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(f"{api_base.rstrip('/')}/v1/querybatch", json={"queries": queries})
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, httpx.TimeoutException) as e:
        logger.warning("OSV enrichment failed: %s", e)
        return items

    results = data.get("results", [])
    if len(results) != len(items):
        logger.warning("OSV batch result length mismatch")
        return items

    enriched: list[VulnerabilityItem] = []
    for i, item in enumerate(items):
        osv_result = results[i] if i < len(results) else {}
        vulns = osv_result.get("vulns", [])

        if not vulns:
            enriched.append(
                VulnerabilityItem(
                    package=item.package,
                    current_version=item.current_version,
                    vulnerability_id=item.vulnerability_id,
                    summary=item.summary,
                    fixed_versions=item.fixed_versions,
                    source=item.source,
                    severity=item.severity,
                    kev_listed=item.kev_listed,
                    priority=item.priority,
                    priority_rationale=item.priority_rationale,
                    aliases=item.aliases or [],
                    osv_enriched=False,
                )
            )
            continue

        # querybatch returns only id and modified; match by vuln id
        osv_ids = [v.get("id", "") for v in vulns if v.get("id")]
        matched = item.vulnerability_id in osv_ids or any(
            a in osv_ids for a in (item.aliases or [])
        )
        if not matched:
            matched = any(item.vulnerability_id.upper() == o.upper() for o in osv_ids)

        enriched.append(
            VulnerabilityItem(
                package=item.package,
                current_version=item.current_version,
                vulnerability_id=item.vulnerability_id,
                summary=item.summary,
                fixed_versions=item.fixed_versions,
                source=item.source,
                severity=item.severity,
                kev_listed=item.kev_listed,
                priority=item.priority,
                priority_rationale=item.priority_rationale,
                aliases=item.aliases or [],
                osv_enriched=matched,
            )
        )

    return enriched
