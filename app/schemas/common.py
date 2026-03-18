"""Common schemas for TaskForge Security."""

from pydantic import BaseModel


class ErrorDetail(BaseModel):
    """Error response detail."""

    code: str
    message: str
    detail: str | None = None
