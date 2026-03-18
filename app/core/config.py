"""Runtime configuration for TaskForge Security."""

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    app_env: Literal["development", "production", "test"] = "development"
    log_level: str = "INFO"
    scan_timeout: int = 120

    # Rate limiting (requests per minute)
    rate_limit_scan: str = "10/minute"

    # API auth: require X-API-Key header for sensitive endpoints when true
    require_api_key: bool = False
    api_key: str = ""

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


@lru_cache
def get_settings() -> Settings:
    """Cached settings instance."""
    return Settings()
