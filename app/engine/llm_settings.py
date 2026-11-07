"""Where the language models live and how long to wait for them.

One OpenAI-compatible endpoint per tier (Ollama and vLLM speak it, as do most hosted
APIs), configured from the environment:

    MIRAGE_LLM_LOCAL__BASE_URL=http://ollama:11434/v1
    MIRAGE_LLM_LOCAL__MODEL=qwen2.5:7b
    MIRAGE_LLM_LOCAL__TIMEOUT_S=3
    MIRAGE_LLM_LOCAL__MAX_TOKENS=512

Only tier 1 (``local``) exists so far; the strong tier is added with tier 2.
"""

from typing import Annotated
from urllib.parse import urlsplit

from pydantic import AfterValidator, BaseModel, ConfigDict, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _http_url(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("must be an http(s) URL with a host")
    return value.rstrip("/")


class TierConfig(BaseModel):
    """Endpoint and limits for one tier."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    # Base URL of the OpenAI-compatible API, including the /v1 prefix.
    base_url: Annotated[str, AfterValidator(_http_url)]
    model: str = Field(min_length=1)
    # Hard deadline for one call; the engine falls back to tier 0 when it passes.
    timeout_s: float = Field(gt=0, le=60)
    # Upper bound on generated tokens: bounds both latency and the budget cost of a call.
    max_tokens: int = Field(gt=0, le=4096)


class LocalTierConfig(TierConfig):
    """Tier 1 defaults: the Ollama service from the compose file.

    The defaults live on a subclass, not on ``TierConfig``, so that setting one
    variable (say only the model) overrides that field and keeps the rest: a nested
    environment value arrives as a partial dict and needs every field to have a default.
    """

    base_url: Annotated[str, AfterValidator(_http_url)] = "http://ollama:11434/v1"
    model: str = Field(default="qwen2.5:7b", min_length=1)
    # Tier 1 target: p95 <= 3 s, so a slower answer is not worth waiting for.
    timeout_s: float = Field(default=3.0, gt=0, le=60)
    max_tokens: int = Field(default=512, gt=0, le=4096)


class LLMSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="MIRAGE_LLM_",
        env_nested_delimiter="__",
        env_file=".env",
        extra="ignore",
    )

    local: LocalTierConfig = LocalTierConfig()
