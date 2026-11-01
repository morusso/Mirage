from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="MIRAGE_",
        env_file=".env",
        extra="ignore",
    )

    environment: Literal["dev", "test", "prod"] = "dev"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    # Internal server (health, metrics). Bind to loopback by default; in Docker
    # bind to 0.0.0.0 inside the container and never publish the port.
    internal_server_enabled: bool = True
    internal_host: str = "127.0.0.1"
    internal_port: int = 8081
