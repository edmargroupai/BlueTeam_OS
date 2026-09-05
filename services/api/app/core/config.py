from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

_ROOT = Path(__file__).resolve().parents[4]
_ENV_FILES = (
    str(_ROOT / ".env"),
    str(_ROOT / ".env.local"),
    ".env",
    ".env.local",
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="BTOS_", env_file=_ENV_FILES, extra="ignore")

    env: str = "development"
    log_level: str = "INFO"
    secret_key: str = Field(default="dev-only-insecure-key-change-me")
    api_host: str = "127.0.0.1"
    api_port: int = 8080
    api_public_url: str = "http://127.0.0.1:8080"
    web_origin: str = "http://127.0.0.1:3000"
    # Comma-separated explicit browser origins for CORS (required for production besides web_origin).
    cors_origins: str = ""
    # Optional regex for preview frontends (e.g. https://.*\\.vercel\\.app). Empty disables regex.
    cors_origin_regex: str = ""
    database_url: str = "sqlite:///./data/blueteam.db"
    redis_url: str = ""
    clickhouse_url: str = ""
    opensearch_url: str = ""
    kafka_bootstrap: str = ""
    s3_endpoint: str = ""
    s3_bucket: str = "blueteam-evidence"
    s3_access_key: str = ""
    s3_secret_key: str = ""
    object_store_root: str = "./data/objects"
    retention_events_days: int = 90
    retention_dead_letter_days: int = 30
    retention_findings_days: int = 365
    supabase_url: str = ""
    supabase_publishable_key: str = ""
    dev_seed: bool = True
    # Shared password for local seed users (never use in production).
    dev_password: str = "dev_only_change_me"
    # Primary local operator email created/updated when BTOS_DEV_SEED=true.
    dev_operator_email: str = "detector@demo.blueteam.local"
    access_token_minutes: int = 30
    refresh_token_days: int = 7
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_jwks_url: str = ""
    ai_enabled: bool = False
    ai_provider: str = ""
    quality_model_version: str = "qi-1.0.0"
    ebpf_enabled: bool = False
    opa_url: str = ""

    @property
    def is_production(self) -> bool:
        return self.env.lower() == "production"

    @property
    def oidc_configured(self) -> bool:
        return bool(self.oidc_issuer and self.oidc_jwks_url)

    def cors_allow_origins(self) -> list[str]:
        origins: list[str] = []
        if self.cors_origins.strip():
            origins.extend(item.strip() for item in self.cors_origins.split(",") if item.strip())
        if self.web_origin.strip():
            origins.append(self.web_origin.strip())
        if not self.is_production:
            origins.extend(["http://localhost:3000", "http://127.0.0.1:3000"])
        deduped: list[str] = []
        for origin in origins:
            if origin and origin not in deduped:
                deduped.append(origin)
        return deduped

    def cors_allow_origin_regex(self) -> str | None:
        value = self.cors_origin_regex.strip()
        if value:
            return value
        if not self.is_production:
            # Local/dev convenience for Vercel preview testing against a local API.
            return r"https://.*\.vercel\.app"
        return None


@lru_cache
def get_settings() -> Settings:
    return Settings()
