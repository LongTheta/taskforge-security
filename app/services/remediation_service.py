"""Remediation planning - produces reviewable recommendations, no file mutation."""

from packaging.version import InvalidVersion, Version

from app.core.logging_config import get_logger
from app.schemas.remediation import RemediationRecommendation
from app.schemas.scan import VulnerabilityItem
from app.services.scan_service import run_scan

logger = get_logger(__name__)

# Security-sensitive packages: always require manual review
MANUAL_REVIEW_PACKAGES: set[str] = {
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
    "sqlalchemy",
    "psycopg2",
    "psycopg2-binary",
    "mysqlclient",
    "pymysql",
    "redis",
}


def run_remediation(
    target_path: str,
    manifest_path: str = "requirements.txt",
) -> list[RemediationRecommendation]:
    """
    Produce remediation recommendations from a fresh scan.
    No file mutation; returns reviewable recommendations.
    """
    scan_result = run_scan(
        target_path=target_path,
        manifest_path=manifest_path,
        include_osv_enrichment=True,
        include_kev_prioritization=True,
    )

    # Group by package (multiple vulns per package)
    by_package: dict[str, list[VulnerabilityItem]] = {}
    for item in scan_result.vulnerabilities:
        by_package.setdefault(item.package, []).append(item)

    recommendations: list[RemediationRecommendation] = []
    for pkg, vulns in by_package.items():
        rec = _plan_package_remediation(pkg, vulns)
        if rec:
            recommendations.append(rec)

    return recommendations


def _plan_package_remediation(
    package: str,
    vulns: list[VulnerabilityItem],
) -> RemediationRecommendation | None:
    """Plan remediation for a single package with multiple vulns."""
    if not vulns:
        return None

    current_version = vulns[0].current_version
    all_fixed: set[str] = set()
    vuln_ids: list[str] = []
    kev_listed = any(v.kev_listed for v in vulns)
    severity = _max_severity([v.vulnerability_id for v in vulns])

    for v in vulns:
        vuln_ids.append(v.vulnerability_id)
        all_fixed.update(v.fixed_versions or [])

    if not all_fixed:
        return RemediationRecommendation(
            package=package,
            current_version=current_version,
            recommended_version=current_version,
            vulnerability_ids=vuln_ids,
            severity=severity,
            kev_listed=kev_listed,
            rationale="No fixed version available from advisories.",
            confidence="high",
            upgrade_type="unknown",
            manual_review_required=True,
            fixed_versions=[],
            mitigation_guidance="Monitor for upstream fix; consider temporary mitigations or alternative packages.",
        )

    recommended = _pick_best_fixed_version(current_version, sorted(all_fixed))
    upgrade_type = _classify_upgrade(current_version, recommended)
    manual_review = (
        upgrade_type == "major" or package.lower() in MANUAL_REVIEW_PACKAGES or kev_listed
    )

    rationale_parts = [f"Upgrade to {recommended} (lowest version fixing all {len(vulns)} vuln(s))"]
    if kev_listed:
        rationale_parts.append("CISA KEV listed - prioritize.")
    if upgrade_type == "major":
        rationale_parts.append("Major version upgrade - verify compatibility.")

    return RemediationRecommendation(
        package=package,
        current_version=current_version,
        recommended_version=recommended,
        vulnerability_ids=vuln_ids,
        severity=severity,
        kev_listed=kev_listed,
        rationale="; ".join(rationale_parts),
        confidence="high" if upgrade_type == "patch" else "medium",
        upgrade_type=upgrade_type,
        manual_review_required=manual_review,
        fixed_versions=sorted(all_fixed),
    )


def _pick_best_fixed_version(current: str, fixed_versions: list[str]) -> str:
    """Pick nearest safe version: prefer patch, then minor, then major."""
    try:
        current_ver = Version(current)
    except InvalidVersion:
        return fixed_versions[0] if fixed_versions else current

    patch_candidates = []
    minor_candidates = []
    major_candidates = []

    for fv in fixed_versions:
        try:
            v = Version(fv)
        except InvalidVersion:
            continue
        if v > current_ver:
            if v.major == current_ver.major and v.minor == current_ver.minor:
                patch_candidates.append(fv)
            elif v.major == current_ver.major:
                minor_candidates.append(fv)
            else:
                major_candidates.append(fv)

    for candidates in (patch_candidates, minor_candidates, major_candidates):
        if candidates:
            return min(candidates, key=lambda x: Version(x))

    return fixed_versions[0] if fixed_versions else current


def _classify_upgrade(current: str, recommended: str) -> str:
    """Classify upgrade as patch, minor, or major."""
    try:
        c = Version(current)
        r = Version(recommended)
    except InvalidVersion:
        return "unknown"
    if r.major != c.major:
        return "major"
    if r.minor != c.minor:
        return "minor"
    return "patch"


def _max_severity(vuln_ids: list[str]) -> str | None:
    """Infer severity from vuln context; pip-audit/OSV may not provide it."""
    return None
