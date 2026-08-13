from functools import lru_cache
from pathlib import Path

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AWE_", extra="ignore")

    app_name: str = "AWE Backend"
    environment: str = "development"
    api_prefix: str = "/api/v1"
    workspace_dir: Path = Field(default=Path.home() / "AWE" / "AtomProjects")
    docker_workspace_dir: Path = Path("/home/user/AWE/.awe-projects")
    legacy_src_dir: Path = Field(
        default=Path(__file__).resolve().parents[2] / "src"
    )
    mongo_uri: str = "mongodb://localhost:27017"
    auth_enabled: bool = True
    secret_key: str = "development-only-change-me"
    admin_password_hash: str = ""
    auth_file: Path = Field(default=Path.home() / ".config" / "awe" / "auth.json")
    session_ttl_seconds: int = 43200
    secure_cookies: bool = False
    browser_proxy_enabled: bool = True
    browser_proxy_host: str = "127.0.0.1"
    browser_proxy_port: int = 8080
    proxy_control_host: str = "127.0.0.1"
    proxy_control_port: int = 0
    proxy_advertise_host: str = "localhost"
    proxy_public_port: int = 8080
    proxy_username: str = ""
    proxy_password: str = ""
    proxy_certificate_path: Path = Path("/data/proxy/AWE/proxycert/CA/rootCACert.pem")

    @model_validator(mode="after")
    def validate_production_security(self):
        if self.environment == "production":
            if self.secret_key == "development-only-change-me" or len(self.secret_key) < 32:
                raise ValueError("AWE_SECRET_KEY must be at least 32 characters in production")
            if not self.secure_cookies:
                raise ValueError("AWE_SECURE_COOKIES must be true in production")
        return self
    allowed_origins: list[str] = ["http://localhost:5173"]


@lru_cache
def get_settings() -> Settings:
    return Settings()
