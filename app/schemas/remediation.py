"""Remediation request and response schemas."""

from pydantic import BaseModel, Field


class RemediationRequest(BaseModel):
    """Request body for POST /api/v1/remediate."""

    vulnerabilities: list[dict] = Field(
        ...,
        description="List of vulnerability objects from scan endpoint",
    )


class RemediationRecommendation(BaseModel):
    """Single remediation recommendation."""

    package: str
    current_version: str
    recommended_version: str
    rationale: str
    confidence: str = Field(..., description="high, medium, or low")


class RemediationResponse(BaseModel):
    """Response from POST /api/v1/remediate."""

    recommendations: list[RemediationRecommendation]
