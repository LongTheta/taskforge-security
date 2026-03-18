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

    # OSV enrichment
    osv_api_base: str = "https://api.osv.dev"
    osv_timeout: int = 30

    # CISA KEV catalog
    kev_catalog_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    kev_timeout: int = 30

    # Rate limiting (requests per minute)
    rate_limit_scan: str = "10/minute"

    # API auth: require X-API-Key header for sensitive endpoints when true
    require_api_key: bool = False
    api_key: str = ""

    # GitHub PR automation (optional)
    github_token: str = ""
    github_owner: str = ""
    github_repo: str = ""
    github_base_branch: str = "main"
    github_dry_run: bool = True

    # Policy gating: block deployment when true
    policy_block_critical: bool = True
    policy_block_kev: bool = True

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def github_configured(self) -> bool:
        return bool(self.github_token and self.github_owner and self.github_repo)


@lru_cache
def get_settings() -> Settings:
    """Cached settings instance."""
    return Settings()
