"""Remediation service - recommends safer versions without modifying files."""

from app.core.logging_config import get_logger
from app.schemas.remediation import RemediationRecommendation, RemediationResponse

logger = get_logger(__name__)


def run_remediation(vulnerabilities: list[dict]) -> RemediationResponse:
    """
    Analyze vulnerabilities and return remediation recommendations.
    Chooses lowest fixed version when available. Does NOT modify files.
    """
    recommendations: list[RemediationRecommendation] = []

    for vuln in vulnerabilities:
        pkg = vuln.get("package") or vuln.get("name")
        current = vuln.get("current_version") or vuln.get("version", "")
        fixed_versions = vuln.get("fixed_versions") or []

        if not pkg:
            continue

        recommended = _choose_recommended_version(current, fixed_versions)
        rationale, confidence = _build_rationale(current, fixed_versions, recommended)

        recommendations.append(
            RemediationRecommendation(
                package=str(pkg),
                current_version=str(current),
                recommended_version=recommended,
                rationale=rationale,
                confidence=confidence,
            )
        )

    return RemediationResponse(recommendations=recommendations)


def _choose_recommended_version(current: str, fixed_versions: list) -> str:
    """Choose lowest fixed version that satisfies semantic ordering."""
    if not fixed_versions:
        return "unknown"

    # Normalize: ensure strings
    fixed = [str(v).strip() for v in fixed_versions if v]

    # Prefer versions that look like >= current (e.g. 1.0.1 for 1.0.0)
    # Simple heuristic: pick lowest by version comparison when possible
    try:
        from packaging.version import Version

        vs = [(Version(v), v) for v in fixed]
        vs.sort(key=lambda x: x[0])
        return vs[0][1]
    except Exception:
        pass

    return fixed[0]


def _build_rationale(current: str, fixed_versions: list, recommended: str) -> tuple[str, str]:
    """Build rationale and confidence."""
    if not fixed_versions:
        return (
            "No fix version available from vulnerability database. Manual review required.",
            "low",
        )
    if recommended == "unknown":
        return ("Could not parse fix versions. Manual review required.", "low")
    return (
        f"Recommended upgrade from {current} to {recommended} (lowest fixed version).",
        "high",
    )
