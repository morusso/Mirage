import asyncio

import structlog
from redis.asyncio import Redis
from redis.exceptions import RedisError

from domain.captured_request import CapturedRequest

logger = structlog.get_logger()


class StreamPublisher:
    """Appends captured requests to a Redis Stream (XADD), trimmed to ~maxlen entries.

    Publishing never raises: the honeypot must keep answering when Redis is slow or
    down. A failed publish is logged (event id only, never attacker payload) and the
    event is dropped. TODO: spool failed events locally to get closer to zero loss.
    """

    def __init__(
        self,
        redis: Redis,
        stream: str,
        *,
        maxlen: int,
        timeout_s: float = 1.0,
    ) -> None:
        self.redis = redis
        self.stream = stream
        self.maxlen = maxlen
        self.timeout_s = timeout_s

    async def publish(self, event: CapturedRequest) -> bool:
        """Returns True if the event reached the stream."""
        try:
            async with asyncio.timeout(self.timeout_s):
                await self.redis.xadd(
                    self.stream,
                    {"data": event.model_dump_json()},
                    maxlen=self.maxlen,
                    approximate=True,
                )
        except (RedisError, OSError, TimeoutError) as exc:
            logger.error(
                "capture_publish_failed",
                event_id=str(event.event_id),
                stream=self.stream,
                error=type(exc).__name__,
            )
            return False
        return True
