"""OSV.dev API enrichment for vulnerability severity and metadata."""

import httpx

from app.schemas.scan import VulnerabilityItem


def enrich_with_osv(
    items: list[VulnerabilityItem],
    api_base: str,
    timeout: int = 30,
) -> list[VulnerabilityItem]:
    """
    Enrich vulnerability items with OSV.dev API data (severity, summary).
    Returns updated items; does not mutate originals.
    """
    if not items:
        return items

    # Build query batch: unique (package, version) pairs
    seen: set[tuple[str, str]] = set()
    queries: list[dict] = []
    for item in items:
        key = (item.package, item.current_version)
        if key in seen:
            continue
        seen.add(key)
        queries.append({
            "package": {"ecosystem": "PyPI", "name": item.package},
            "version": item.current_version,
        })

    url = f"{api_base.rstrip('/')}/v1/querybatch"
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(url, json={"queries": queries})
            resp.raise_for_status()
            results = resp.json()
    except (httpx.HTTPError, httpx.TimeoutException):
        # Log but don't fail - return original items
        return items

    # Map (package, version) -> severity from OSV
    severity_map: dict[tuple[str, str], str] = {}
    for i, batch_result in enumerate(results.get("results", [])):
        if i >= len(queries):
            break
        pkg = queries[i]["package"]["name"]
        ver = queries[i]["version"]
        vulns = batch_result.get("vulns", [])
        for v in vulns:
            sev = _extract_severity(v)
            if sev and sev != "unknown":
                key = (pkg, ver)
                if key not in severity_map or _severity_rank(sev) > _severity_rank(severity_map[key]):
                    severity_map[key] = sev

    # Apply enrichment
    enriched: list[VulnerabilityItem] = []
    for item in items:
        key = (item.package, item.current_version)
        new_severity = severity_map.get(key, item.severity)
        enriched.append(
            VulnerabilityItem(
                package=item.package,
                current_version=item.current_version,
                vulnerability_id=item.vulnerability_id,
                severity=new_severity,
                summary=item.summary,
                fixed_versions=item.fixed_versions,
                source=item.source,
            )
        )
    return enriched


def _extract_severity(vuln: dict) -> str | None:
    """Extract severity from OSV vulnerability (database_specific or severity)."""
    db = vuln.get("database_specific", {}) or {}
    sev = db.get("severity")
    if sev:
        return str(sev).lower()
    for s in vuln.get("severity", []):
        if isinstance(s, dict) and s.get("type") == "CVSS_V3":
            score = s.get("score", "")
            if score:
                try:
                    f = float(score)
                    if f >= 9.0:
                        return "critical"
                    if f >= 7.0:
                        return "high"
                    if f >= 4.0:
                        return "medium"
                    return "low"
                except (TypeError, ValueError):
                    pass
    return None


def _severity_rank(sev: str) -> int:
    """Higher = more severe."""
    return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(sev.lower(), 0)
