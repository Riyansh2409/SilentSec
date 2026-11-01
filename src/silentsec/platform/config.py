"""Explicit deployment configuration; unsafe development defaults fail closed."""

from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SILENTSEC_PLATFORM_", extra="forbid")
    environment: Literal["development", "test", "production"] = "development"
    database_url: SecretStr = SecretStr("sqlite:///./.platform/platform.db")
    data_dir: Path = Path(".platform")
    public_url: str = "http://127.0.0.1:8780"
    allowed_origins: list[str] = []
    session_secret: SecretStr
    dev_login_code: SecretStr = SecretStr("")
    auth_mode: Literal["development", "oidc"] = "development"
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: SecretStr = SecretStr("")
    oidc_audience: str = ""
    oidc_jwks_url: str = ""
    oidc_mfa_acr: list[str] = []
    redis_url: SecretStr = SecretStr("")
    isolated_workers: bool = False
    session_seconds: int = 3600
    admin_session_seconds: int = 900
    reauth_seconds: int = 300
    job_lease_seconds: int = 1200
    auto_worker: bool = False
    payment_webhook_secret: SecretStr = SecretStr("")
    static_dir: Path | None = None
    workstation_enabled: bool = False

    @model_validator(mode="after")
    def validate_deployment(self):
        if len(self.session_secret.get_secret_value()) < 32:
            raise ValueError("Set a random session secret of at least 32 characters.")
        origin = urlsplit(self.public_url)
        if origin.path not in {"", "/"} or origin.query or origin.fragment or origin.username:
            raise ValueError("public_url must be an origin without credentials or paths.")
        if self.environment != "production" and origin.hostname not in {
            "localhost",
            "127.0.0.1",
            "::1",
        }:
            raise ValueError("Development/test servers must use a loopback public URL.")
        if self.auth_mode == "development" and len(self.dev_login_code.get_secret_value()) < 16:
            raise ValueError("Development authentication requires a local access code (16+ chars).")
        if self.auth_mode == "development":
            database = self.database_url.get_secret_value()
            if not database.startswith("sqlite") and urlsplit(database).hostname not in {
                "localhost",
                "127.0.0.1",
                "::1",
            }:
                raise ValueError("Development authentication may only connect to a local database.")
        if self.auth_mode == "oidc":
            if not all(
                (self.oidc_issuer, self.oidc_client_id, self.oidc_audience, self.oidc_jwks_url)
            ):
                raise ValueError(
                    "OIDC requires issuer, client ID, API audience and trusted JWKS URL."
                )
            if any(urlsplit(u).scheme != "https" for u in (self.oidc_issuer, self.oidc_jwks_url)):
                raise ValueError("OIDC issuer and JWKS URL must use HTTPS.")
            if not self.oidc_client_secret.get_secret_value():
                raise ValueError("Configure the confidential OIDC client secret.")
        if self.environment == "production":
            if self.workstation_enabled:
                raise ValueError("Local workstation operations cannot be enabled in production.")
            if not self.database_url.get_secret_value().startswith("postgresql+psycopg://"):
                raise ValueError("Production requires PostgreSQL using Psycopg.")
            if self.auth_mode != "oidc" or self.dev_login_code.get_secret_value():
                raise ValueError("Development authentication is forbidden in production.")
            if origin.scheme != "https" or not self.allowed_origins or "*" in self.allowed_origins:
                raise ValueError("Production requires HTTPS and explicit allowed origins.")
            if (
                not self.redis_url.get_secret_value()
                or not self.isolated_workers
                or self.auto_worker
            ):
                raise ValueError("Production requires Redis and separately isolated workers.")
        return self

    @property
    def origin(self):
        return self.public_url.rstrip("/")

    @property
    def cookie_name(self):
        return "__Host-silentsec" if self.environment == "production" else "silentsec_dev"

    @property
    def oidc_cookie_name(self):
        return "__Host-silentsec-oidc" if self.environment == "production" else "ssec_oidc"
