"""Policy gate endpoint - pass/fail for deployment based on scan results."""

from fastapi import APIRouter, Depends, HTTPException, Request

from app.core.auth import verify_api_key
from app.core.config import get_settings
from app.core.logging_config import get_logger
from app.core.metrics import gate_checks_total, gate_failures_total
from app.core.rate_limit import limiter
from app.services.scan_service import run_scan

router = APIRouter(prefix="/gate", tags=["gate"])
logger = get_logger(__name__)


@router.get("")
@limiter.limit("10/minute")
def get_gate(
    request: Request,
    target_path: str = ".",
    manifest_path: str = "requirements.txt",
    _: None = Depends(verify_api_key),
):
    """
    GET /api/v1/gate
    Policy gate: returns pass/fail for deployment based on scan.
    Blocks when policy_block_critical and critical findings exist, or
    policy_block_kev and KEV-listed findings exist.
    """
    settings = get_settings()
    try:
        result = run_scan(
            target_path=target_path,
            manifest_path=manifest_path,
            include_osv_enrichment=True,
            include_kev_prioritization=True,
        )
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    blocked_reasons: list[str] = []
    if settings.policy_block_critical and result.risk_summary:
        if result.risk_summary.critical_count > 0:
            blocked_reasons.append(
                f"critical:{result.risk_summary.critical_count}"
            )
            gate_failures_total.labels(reason="critical").inc()
    if settings.policy_block_kev and result.risk_summary:
        if result.risk_summary.kev_count > 0:
            blocked_reasons.append(f"kev:{result.risk_summary.kev_count}")
            gate_failures_total.labels(reason="kev").inc()

    gate_checks_total.inc()
    pass_gate = len(blocked_reasons) == 0
    return {
        "pass": pass_gate,
        "blocked_by": blocked_reasons,
        "reason": "; ".join(blocked_reasons) if blocked_reasons else "No blocking findings",
        "risk_summary": result.risk_summary.model_dump() if result.risk_summary else None,
        "vulnerability_count": result.vulnerability_count,
    }
