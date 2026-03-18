"""GitHub API client - minimal scaffolding for PR creation."""

from app.core.config import get_settings
from app.core.logging_config import get_logger
from app.integrations.github.models import PRPayload

logger = get_logger(__name__)


def create_pr_from_payload(payload: PRPayload) -> dict | None:
    """
    Create a PR from payload. Only runs when GITHUB_DRY_RUN=false.
    Returns PR dict or None if dry-run or not configured.
    """
    settings = get_settings()
    if settings.github_dry_run:
        logger.info("GITHUB_DRY_RUN=true; skipping PR creation")
        return None
    if not settings.github_configured:
        logger.warning("GitHub not configured; skipping PR creation")
        return None

    # Scaffolding: actual implementation would use httpx or PyGithub
    # to: 1) create branch, 2) push file changes, 3) create PR
    logger.info(
        "PR creation not implemented; would create branch=%s, title=%s",
        payload.branch_name,
        payload.pr_title,
    )
    return None
