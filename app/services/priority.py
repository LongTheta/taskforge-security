"""Priority calculation - KEV, severity, and component weighting."""

from app.schemas.scan import VulnerabilityItem

# Security-sensitive packages
SECURITY_SENSITIVE: set[str] = {
    "cryptography",
    "pyjwt",
    "jwt",
    "authlib",
    "passlib",
    "bcrypt",
    "paramiko",
    "requests",
    "urllib3",
    "httpx",
    "aiohttp",
}


def _normalize_severity(sev: str | None) -> str | None:
    if not sev:
        return None
    s = sev.lower()
    if s in ("critical", "high", "medium", "low"):
        return s
    return None


def compute_priority(item: VulnerabilityItem) -> tuple[str, str]:
    """Return (priority, rationale)."""
    priority = "low"
    reasons: list[str] = []

    if item.kev_listed:
        priority = "critical"
        reasons.append("CISA KEV listed")
        return (priority, "; ".join(reasons))

    severity = _normalize_severity(item.severity)
    if severity == "critical":
        priority = "critical"
        reasons.append("critical severity")
    elif severity == "high":
        priority = "high"
        reasons.append("high severity")

    if item.package.lower() in SECURITY_SENSITIVE:
        if priority == "low":
            priority = "medium"
        reasons.append("security-sensitive package")

    if item.fixed_versions:
        reasons.append("fix available")
    else:
        if priority in ("low", "medium"):
            priority = "high" if priority == "medium" else "medium"
        reasons.append("no fix available")

    if not reasons:
        reasons.append("default")
    return (priority, "; ".join(reasons))


def apply_priorities(items: list[VulnerabilityItem]) -> list[VulnerabilityItem]:
    """Apply priority and rationale to each item."""
    result: list[VulnerabilityItem] = []
    for item in items:
        priority, rationale = compute_priority(item)
        result.append(
            VulnerabilityItem(
                package=item.package,
                current_version=item.current_version,
                vulnerability_id=item.vulnerability_id,
                summary=item.summary,
                fixed_versions=item.fixed_versions,
                source=item.source,
                severity=item.severity,
                kev_listed=item.kev_listed,
                priority=priority,
                priority_rationale=rationale,
                aliases=item.aliases,
                osv_enriched=item.osv_enriched,
            )
        )
    return result
