"""GitHub PR payload models."""

from pydantic import BaseModel, Field


class PRPayload(BaseModel):
    """Payload for creating a remediation PR."""

    branch_name: str
    pr_title: str
    pr_body: str
    commit_message: str
    file_changes: list[dict[str, str]] = Field(
        default_factory=list,
        description="List of {path, content} for files to create/update",
    )
