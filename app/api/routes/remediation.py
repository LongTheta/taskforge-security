"""Remediation planning endpoint."""

from fastapi import APIRouter, Depends, HTTPException, Request

from app.core.auth import verify_api_key
from app.core.logging_config import get_logger
from app.core.rate_limit import limiter
from app.integrations.github.create_pr import create_pr
from app.integrations.github.pr_creator import prepare_pr_payload, validate_github_config
from app.schemas.remediation import RemediateRequest, RemediateResponse
from app.services.remediation_service import run_remediation

router = APIRouter(prefix="/remediate", tags=["remediation"])
logger = get_logger(__name__)


@router.post("", response_model=RemediateResponse)
@limiter.limit("5/minute")
def post_remediate(
    request: Request,
    body: RemediateRequest,
    _: None = Depends(verify_api_key),
) -> RemediateResponse:
    """
    POST /api/v1/remediate
    Produce reviewable remediation recommendations. No file mutation.
    """
    request_id = getattr(request.state, "request_id", "unknown")
    extra = {
        "request_id": request_id,
        "endpoint": "/api/v1/remediate",
        "target_path": body.target_path,
        "manifest_path": body.manifest_path,
    }

    try:
        recommendations = run_remediation(
            target_path=body.target_path,
            manifest_path=body.manifest_path,
        )
        manual_count = sum(1 for r in recommendations if r.manual_review_required)
        no_fix_count = sum(1 for r in recommendations if r.recommended_version == r.current_version)
        return RemediateResponse(
            recommendations=recommendations,
            recommendation_count=len(recommendations),
            manual_review_count=manual_count,
            no_fix_count=no_fix_count,
        )
    except FileNotFoundError as e:
        logger.warning("Remediation failed: file not found", extra={**extra, "error": str(e)})
        raise HTTPException(status_code=404, detail=str(e)) from e
    except ValueError as e:
        logger.warning("Remediation failed: validation error", extra={**extra, "error": str(e)})
        raise HTTPException(status_code=400, detail=str(e)) from e
    except (RuntimeError, TimeoutError) as e:
        logger.exception("Remediation failed", extra=extra)
        raise HTTPException(
            status_code=500,
            detail="Remediation failed. Check logs for details.",
        ) from e


@router.get("/preview-pr")
@limiter.limit("5/minute")
def get_preview_pr(
    request: Request,
    target_path: str = ".",
    manifest_path: str = "requirements.txt",
    _: None = Depends(verify_api_key),
):
    """
    GET /api/v1/remediate/preview-pr
    Preview PR payload for remediation. Dry-run only; no GitHub calls.
    """
    valid, msg = validate_github_config()
    recommendations = run_remediation(
        target_path=target_path,
        manifest_path=manifest_path,
    )
    payload = prepare_pr_payload(
        recommendations=recommendations,
        manifest_path=manifest_path,
        dry_run=True,
    )
    return {
        "github_configured": valid,
        "github_config_message": msg,
        "recommendation_count": len(recommendations),
        "payload": payload.model_dump(),
    }


@router.post("/create-pr")
@limiter.limit("5/minute")
def post_create_pr(
    request: Request,
    body: RemediateRequest,
    _: None = Depends(verify_api_key),
):
    """
    POST /api/v1/remediate/create-pr
    Create a remediation PR via GitHub API. Requires GITHUB_TOKEN, GITHUB_OWNER, GITHUB_REPO.
    Set GITHUB_DRY_RUN=false to actually create PRs.
    """
    valid, msg = validate_github_config()
    if not valid:
        raise HTTPException(status_code=400, detail=msg)

    try:
        pr = create_pr(
            target_path=body.target_path,
            manifest_path=body.manifest_path,
        )
        if pr is None:
            return {
                "created": False,
                "message": "No PR created (dry-run, no recommendations, or no changes)",
            }
        return {
            "created": True,
            "pr_number": pr["number"],
            "pr_url": pr["html_url"],
            "branch": pr["head"]["ref"],
        }
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        logger.exception("Create PR failed")
        raise HTTPException(
            status_code=500,
            detail="Create PR failed. Check logs for details.",
        ) from e
