"""Remediation endpoint."""

from fastapi import APIRouter, Request

from app.schemas.remediation import RemediationRequest, RemediationResponse
from app.services.remediation_service import run_remediation

router = APIRouter(prefix="/remediate", tags=["remediation"])


@router.post("", response_model=RemediationResponse)
def post_remediate(request: Request, body: RemediationRequest) -> RemediationResponse:
    """
    POST /api/v1/remediate
    Analyze vulnerabilities and return remediation recommendations.
    Does NOT modify files - recommendations only.
    """
    return run_remediation(body.vulnerabilities)
