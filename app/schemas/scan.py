"""Scan request and response schemas."""

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    """Request body for POST /api/v1/scan."""

    target_path: str = Field(..., description="Path to the project directory to scan")
    manifest_path: str = Field(
        default="requirements.txt", description="Path to manifest file relative to target_path"
    )
    include_osv_enrichment: bool = Field(
        default=True, description="Enrich findings with OSV.dev API"
    )
    include_kev_prioritization: bool = Field(
        default=True, description="Flag findings in CISA KEV catalog"
    )


class ScanImageRequest(BaseModel):
    """Request body for POST /api/v1/scan/image."""

    image_ref: str = Field(
        ...,
        description="Container image reference (e.g. python:3.11-slim, myregistry/app:v1)",
    )
    include_kev_prioritization: bool = Field(
        default=True, description="Flag findings in CISA KEV catalog"
    )


class VulnerabilityItem(BaseModel):
    """Single vulnerability in scan results."""

    package: str
    current_version: str
    vulnerability_id: str
    summary: str
    fixed_versions: list[str] = Field(default_factory=list)
    source: str = Field(default="pip-audit", description="pip-audit or osv")
    severity: str | None = Field(default=None, description="critical, high, medium, low")
    kev_listed: bool = Field(default=False, description="In CISA Known Exploited catalog")
    priority: str | None = Field(default=None, description="critical, high, medium, low")
    priority_rationale: str | None = Field(default=None)
    aliases: list[str] = Field(default_factory=list, description="CVE/alias IDs from OSV")
    osv_enriched: bool = Field(default=False, description="Enriched by OSV")


class RiskSummary(BaseModel):
    """Summary of risk across findings."""

    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    kev_count: int = 0


class ScanResponse(BaseModel):
    """Response from POST /api/v1/scan."""

    vulnerability_count: int
    vulnerabilities: list[VulnerabilityItem]
    risk_summary: RiskSummary | None = Field(default=None)
    osv_enrichment_available: bool = Field(default=False)
    kev_prioritization_available: bool = Field(default=False)
