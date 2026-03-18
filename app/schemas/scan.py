"""Scan request and response schemas."""

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    """Request body for POST /api/v1/scan."""

    target_path: str = Field(..., description="Path to the project directory to scan")
    manifest_path: str = Field(default="requirements.txt", description="Path to manifest file relative to target_path")
    include_osv_enrichment: bool = Field(default=False, description="Enrich results with OSV.dev API")


class VulnerabilityItem(BaseModel):
    """Single vulnerability in scan results."""

    package: str
    current_version: str
    vulnerability_id: str
    severity: str = "unknown"
    summary: str
    fixed_versions: list[str] = Field(default_factory=list)
    source: str = Field(..., description="pip-audit or osv")


class ScanResponse(BaseModel):
    """Response from POST /api/v1/scan."""

    total_vulnerabilities: int
    vulnerabilities: list[VulnerabilityItem]
