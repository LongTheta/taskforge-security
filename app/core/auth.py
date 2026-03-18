"""Lightweight API key auth for sensitive endpoints."""

from fastapi import Header, HTTPException

from app.core.config import get_settings


def verify_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    """
    Verify X-API-Key header when REQUIRE_API_KEY is true.
    Raises 401 if key is missing or invalid.
    """
    settings = get_settings()
    if not settings.require_api_key:
        return
    if not settings.api_key:
        return  # No key configured; skip check (dev mode)
    if not x_api_key or x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Missing or invalid API key")
