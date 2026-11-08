import asyncio

import structlog
from pydantic import ValidationError
from redis.asyncio import Redis
from redis.exceptions import RedisError

from app.engine.response import GeneratedResponse

logger = structlog.get_logger()

KEY_PREFIX = "mirage:cache:t0:"
DEFAULT_TTL_S = 24 * 3600


class ResponseCache:
    """Tier 0 response cache in Redis, keyed by request signature.

    Never raises: a cache that is down or holds garbage behaves like an empty one, so
    the honeypot keeps answering (from templates or a model) instead of failing.
    """

    def __init__(self, redis: Redis, *, ttl_s: int = DEFAULT_TTL_S, timeout_s: float = 0.2) -> None:
        self.redis = redis
        self.ttl_s = ttl_s
        self.timeout_s = timeout_s

    @staticmethod
    def _key(signature: str) -> str:
        return KEY_PREFIX + signature

    async def get(self, signature: str) -> GeneratedResponse | None:
        try:
            async with asyncio.timeout(self.timeout_s):
                raw = await self.redis.get(self._key(signature))
        except (RedisError, OSError, TimeoutError) as exc:
            logger.warning("response_cache_get_failed", error=type(exc).__name__)
            return None
        if raw is None:
            return None
        try:
            return GeneratedResponse.model_validate_json(raw)
        except ValidationError:
            logger.warning("response_cache_entry_invalid")
            return None

    async def has(self, signature: str) -> bool:
        try:
            async with asyncio.timeout(self.timeout_s):
                return bool(await self.redis.exists(self._key(signature)))
        except (RedisError, OSError, TimeoutError) as exc:
            logger.warning("response_cache_has_failed", error=type(exc).__name__)
            return False

    async def set(self, signature: str, response: GeneratedResponse) -> bool:
        """Store a response; returns False if it could not be written."""
        try:
            async with asyncio.timeout(self.timeout_s):
                await self.redis.set(
                    self._key(signature), response.model_dump_json(), ex=self.ttl_s
                )
        except (RedisError, OSError, TimeoutError) as exc:
            logger.warning("response_cache_set_failed", error=type(exc).__name__)
            return False
        return True
