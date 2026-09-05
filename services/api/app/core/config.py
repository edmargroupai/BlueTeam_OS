from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="BTOS_", env_file=(".env", ".env.local"), extra="ignore")

    env: str = "development"
    log_level: str = "INFO"
    secret_key: str = Field(default="dev-only-insecure-key-change-me")
    api_host: str = "127.0.0.1"
    api_port: int = 8080
    api_public_url: str = "http://127.0.0.1:8080"
    web_origin: str = "http://127.0.0.1:3000"
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
    dev_password: str = "dev_only_change_me"
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


@lru_cache
def get_settings() -> Settings:
    return Settings()
