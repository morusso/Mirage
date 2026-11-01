from ipaddress import IPv4Network, IPv6Network
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

    # Peers allowed to set X-Forwarded-For (e.g. the Caddy container network).
    # Empty by default: trust nobody and use the socket peer address.
    # Env example: MIRAGE_TRUSTED_PROXIES='["172.16.0.0/12"]'
    trusted_proxies: list[IPv4Network | IPv6Network] = []
