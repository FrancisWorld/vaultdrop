from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VAULTDROP_", env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./vaultdrop.db"
    aws_region: str = "us-east-1"
    s3_bucket: str = "replace-me"
    s3_endpoint: str | None = None
    default_quota_bytes: int = 1_073_741_824
    cors_origins: str = "http://localhost:8000"
    presigned_expiry_seconds: int = 900
    session_secret: str = "replace-me-local-development-secret"
    password_attempt_limit: int = 5


@lru_cache
def get_settings() -> Settings:
    return Settings()
