"""Remediation request and response schemas."""

from typing import Literal

from pydantic import BaseModel, Field


class RemediateRequest(BaseModel):
    """Request body for POST /api/v1/remediate."""

    target_path: str = Field(..., description="Path to the project directory")
    manifest_path: str = Field(
        default="requirements.txt", description="Path to manifest file relative to target_path"
    )
    reuse_scan_results: bool = Field(
        default=False,
        description="If true, run fresh scan; if false and scan was recent, could reuse (not implemented yet)",
    )


class RemediationRecommendation(BaseModel):
    """Single remediation recommendation - reviewable, no file mutation."""

    package: str
    current_version: str
    recommended_version: str
    vulnerability_ids: list[str] = Field(default_factory=list)
    severity: str | None = None
    kev_listed: bool = False
    rationale: str
    confidence: Literal["high", "medium", "low"] = "medium"
    upgrade_type: Literal["patch", "minor", "major", "unknown"] = "unknown"
    manual_review_required: bool = False
    fixed_versions: list[str] = Field(default_factory=list)
    mitigation_guidance: str | None = Field(
        default=None, description="When no fix exists, guidance for mitigation"
    )


class RemediateResponse(BaseModel):
    """Response from POST /api/v1/remediate."""

    recommendations: list[RemediationRecommendation]
    recommendation_count: int
    manual_review_count: int
    no_fix_count: int
