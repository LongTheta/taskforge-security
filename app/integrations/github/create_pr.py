"""GitHub PR creation - creates branch, commits changes, opens PR."""

import base64
import re
from pathlib import Path

import httpx

from app.core.config import get_settings
from app.core.logging_config import get_logger
from app.integrations.github.models import PRPayload
from app.schemas.remediation import RemediationRecommendation

logger = get_logger(__name__)

GITHUB_API = "https://api.github.com"


def _apply_manifest_updates(
    content: str, recommendations: list[RemediationRecommendation]
) -> str:
    """Update requirements.txt content with recommended versions."""
    lines = content.splitlines()
    by_pkg = {r.package.lower(): r for r in recommendations}
    result: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            result.append(line)
            continue
        # Match: package or package==x.y.z or package>=x.y.z etc.
        match = re.match(r"^([a-zA-Z0-9_-]+)\s*([=<>!~].*)?$", stripped)
        if match:
            pkg = match.group(1).lower()
            if pkg in by_pkg:
                r = by_pkg[pkg]
                if r.recommended_version != r.current_version:
                    indent = line[: len(line) - len(line.lstrip())]
                    result.append(f"{indent}{r.package}=={r.recommended_version}")
                    continue
        result.append(line)
    return "\n".join(result) + ("\n" if content.endswith("\n") else "")


def create_pr(
    target_path: str,
    manifest_path: str = "requirements.txt",
) -> dict | None:
    """
    Create remediation PR via GitHub API.
    Reads manifest from target_path, applies updates, creates branch + PR.
    Returns PR dict or None if dry-run or error.
    """
    settings = get_settings()
    if settings.github_dry_run:
        logger.info("GITHUB_DRY_RUN=true; skipping PR creation")
        return None
    if not settings.github_configured:
        logger.warning("GitHub not configured")
        return None

    from app.services.remediation_service import run_remediation

    recommendations = run_remediation(target_path=target_path, manifest_path=manifest_path)
    if not recommendations:
        logger.info("No remediation recommendations; skipping PR")
        return None

    # Filter to those with actual changes
    to_apply = [r for r in recommendations if r.recommended_version != r.current_version]
    if not to_apply:
        logger.info("No version changes to apply")
        return None

    manifest_file = Path(target_path) / manifest_path
    if not manifest_file.exists():
        logger.error("Manifest not found: %s", manifest_file)
        return None

    content = manifest_file.read_text(encoding="utf-8", errors="replace")
    new_content = _apply_manifest_updates(content, to_apply)
    if new_content == content:
        logger.info("No content changes after applying updates")
        return None

    headers = {
        "Authorization": f"Bearer {settings.github_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    owner = settings.github_owner
    repo = settings.github_repo
    base_branch = settings.github_base_branch

    branch_name = "security/remediation-deps"
    if to_apply:
        pkgs = "-".join(r.package for r in to_apply[:3])
        if len(to_apply) > 3:
            pkgs += f"-and-{len(to_apply)-3}-more"
        branch_name = f"security/remediation-{pkgs}"[:80]

    commit_message = "chore(security): remediate vulnerable dependencies\n\n"
    for r in to_apply:
        commit_message += f"- {r.package}: {r.current_version} -> {r.recommended_version}\n"

    try:
        with httpx.Client(timeout=30) as client:
            # Get base branch sha
            r = client.get(
                f"{GITHUB_API}/repos/{owner}/{repo}/git/ref/heads/{base_branch}",
                headers=headers,
            )
            r.raise_for_status()
            base_sha = r.json()["object"]["sha"]

            # Create branch
            r = client.post(
                f"{GITHUB_API}/repos/{owner}/{repo}/git/refs",
                headers=headers,
                json={"ref": f"refs/heads/{branch_name}", "sha": base_sha},
            )
            if r.status_code == 422 and "already exists" in r.text.lower():
                logger.warning("Branch %s already exists", branch_name)
                return None
            r.raise_for_status()

            # Get file sha (for update)
            r = client.get(
                f"{GITHUB_API}/repos/{owner}/{repo}/contents/{manifest_path}",
                headers=headers,
                params={"ref": branch_name},
            )
            r.raise_for_status()
            file_sha = r.json()["sha"]

            # Update file
            encoded = base64.b64encode(new_content.encode("utf-8")).decode("ascii")
            r = client.put(
                f"{GITHUB_API}/repos/{owner}/{repo}/contents/{manifest_path}",
                headers=headers,
                json={
                    "message": commit_message.strip(),
                    "content": encoded,
                    "sha": file_sha,
                    "branch": branch_name,
                },
            )
            r.raise_for_status()

            # Create PR
            pr_body = "## Remediation Summary\n\n"
            pr_body += "This PR updates vulnerable dependencies.\n\n"
            for rec in to_apply:
                pr_body += f"- **{rec.package}**: {rec.current_version} → {rec.recommended_version}\n"
            pr_body += "\n---\n*Generated by TaskForge Security. Review before merging.*\n"

            r = client.post(
                f"{GITHUB_API}/repos/{owner}/{repo}/pulls",
                headers=headers,
                json={
                    "title": "chore(security): remediate vulnerable dependencies",
                    "body": pr_body,
                    "head": branch_name,
                    "base": base_branch,
                },
            )
            r.raise_for_status()
            pr = r.json()
            logger.info("Created PR #%s: %s", pr["number"], pr["html_url"])
            return pr
    except httpx.HTTPError as e:
        logger.exception("GitHub API error: %s", e)
        raise
