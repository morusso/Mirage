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
