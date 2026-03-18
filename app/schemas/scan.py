"""Scan request and response schemas."""

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    """Request body for POST /api/v1/scan."""

    target_path: str = Field(..., description="Path to the project directory to scan")
    manifest_path: str = Field(
        default="requirements.txt", description="Path to manifest file relative to target_path"
    )


class VulnerabilityItem(BaseModel):
    """Single vulnerability in scan results."""

    package: str
    current_version: str
    vulnerability_id: str
    summary: str
    fixed_versions: list[str] = Field(default_factory=list)


class ScanResponse(BaseModel):
    """Response from POST /api/v1/scan."""

    vulnerability_count: int
    vulnerabilities: list[VulnerabilityItem]
