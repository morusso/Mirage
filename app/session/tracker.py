"""Per-session request counters in Redis: how many requests, and how far apart.

One hash per session, written by one Lua script so concurrent requests of the same
session (a scanner with many workers) cannot lose updates::

    mirage:session:<session_id>    count   requests seen
                                   gap_ms  sum of the gaps between consecutive requests
                                   last    time of the latest request, ms

The mean interval is ``gap_ms / (count - 1)``: a running sum instead of a list of
timestamps keeps a session at three fields however long it goes on. Every write
refreshes the TTL, so a session that goes quiet disappears from Redis after
``DEFAULT_TTL_S``; that matches the inactivity after which the sessionizer closes it.

The clock is the server's, never anything the client sent, so an attacker cannot fake
the rhythm of a human by lying about timestamps. Like the response cache, this never
raises: if Redis is down, ``record`` returns None and the caller routes the request as
the first of a session.
"""

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass
from uuid import UUID

import structlog
from redis.asyncio import Redis
from redis.exceptions import RedisError

logger = structlog.get_logger()

KEY_PREFIX = "mirage:session:"
DEFAULT_TTL_S = 30 * 60

_RECORD_LUA = """
local now = tonumber(ARGV[1])
local last = tonumber(redis.call('HGET', KEYS[1], 'last'))
local gap = 0
if last then
    gap = math.max(0, now - last)
    now = math.max(now, last)
end
local count = redis.call('HINCRBY', KEYS[1], 'count', 1)
local total = redis.call('HINCRBY', KEYS[1], 'gap_ms', gap)
redis.call('HSET', KEYS[1], 'last', now)
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2]))
return {count, total}
"""


@dataclass(frozen=True, slots=True)
class SessionCounters:
    request_count: int
    mean_interval_s: float


class SessionTracker:
    def __init__(
        self,
        redis: Redis,
        *,
        ttl_s: int = DEFAULT_TTL_S,
        timeout_s: float = 0.2,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.redis = redis
        self.ttl_s = ttl_s
        self.timeout_s = timeout_s
        self.clock = clock
        self._record = redis.register_script(_RECORD_LUA)

    @staticmethod
    def _key(session_id: UUID) -> str:
        return f"{KEY_PREFIX}{session_id}"

    async def record(self, session_id: UUID) -> SessionCounters | None:
        """Count one more request of the session; None if Redis could not answer."""
        now_ms = int(self.clock() * 1000)
        try:
            async with asyncio.timeout(self.timeout_s):
                count, gap_ms = await self._record(
                    keys=[self._key(session_id)], args=[now_ms, self.ttl_s]
                )
        except (RedisError, OSError, TimeoutError) as exc:
            logger.warning("session_record_failed", error=type(exc).__name__)
            return None
        count, gap_ms = int(count), int(gap_ms)
        mean = gap_ms / (count - 1) / 1000 if count > 1 else 0.0
        return SessionCounters(request_count=count, mean_interval_s=mean)
