from functools import lru_cache
from typing import Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration, read from `VAULTDROP_*` environment variables."""

    model_config = SettingsConfigDict(env_prefix="VAULTDROP_", env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./vaultdrop.db"
    auto_migrate: bool = True

    aws_region: str = "us-east-1"
    s3_bucket: str = Field(default="vaultdrop-local", min_length=3, max_length=63)
    s3_endpoint: str | None = None
    s3_public_endpoint: str | None = None
    s3_path_style: bool = False
    s3_bootstrap: bool = False
    s3_sse: str | None = "aws:kms"
    s3_kms_key_id: str | None = None
    presigned_expiry_seconds: int = Field(default=900, ge=60, le=3600)

    default_quota_bytes: int = Field(default=1_073_741_824, ge=0)
    upload_ttl_hours: int = Field(default=24, ge=1, le=168)
    allowed_origins: str = "http://localhost:8000,http://127.0.0.1:8000"
    allow_registration: bool = True

    session_ttl_seconds: int = Field(default=7 * 86400, ge=300)
    cookie_secure: bool = True
    password_attempt_limit: int = Field(default=5, ge=1)
    login_attempt_limit: int = Field(default=5, ge=1)
    attempt_window_seconds: int = Field(default=900, ge=1)
    argon2_memory_kib: int = Field(default=19456, ge=8)
    argon2_time_cost: int = Field(default=2, ge=1)
    argon2_parallelism: int = Field(default=1, ge=1)

    sweep_interval_seconds: int = Field(default=900, ge=0)

    @field_validator("s3_endpoint", "s3_public_endpoint", "s3_sse", "s3_kms_key_id", mode="before")
    @classmethod
    def blank_is_none(cls, value: Any) -> Any:
        return None if isinstance(value, str) and not value.strip() else value

    @property
    def origins(self) -> frozenset[str]:
        return frozenset(
            o.strip().rstrip("/") for o in self.allowed_origins.split(",") if o.strip()
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
