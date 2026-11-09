"""Atomic multi-key sliding-window budget check, as one Redis Lua script.

Each budget dimension (an IP, a subnet, the whole honeypot) is one Redis hash holding
a token count for the current time bucket and for the one before it. The usage inside
the sliding window is estimated by weighting the previous bucket by how much of it the
window still covers::

    used = previous * (1 - elapsed_in_bucket / window) + current

That is O(1) per key with two counters (no per-event sorted set) and is exact at the
bucket edges; in between it errs by at most the difference in rate between the two
buckets. Good enough for a limit whose purpose is to keep a scanner from monopolising
the model.

The script checks every dimension before charging any: either all of them are charged
or none is, so a request refused on the global limit does not eat the IP's allowance.
It runs in a single round trip and Redis executes scripts atomically, which is what
keeps concurrent requests from overshooting a limit.
"""

from collections.abc import Sequence

from redis.asyncio import Redis
from redis.commands.core import AsyncScript

# KEYS[i]  one hash per dimension
# ARGV[1]  now, in milliseconds
# ARGV[2]  window length, in milliseconds
# ARGV[3]  cost of this request, in tokens
# ARGV[3+i] limit of KEYS[i], in tokens per window; 0 or less means unlimited
# Returns {1, 0} when every dimension was charged, else {0, i}: the first
# dimension (1-based) that had no room.
SLIDING_WINDOW_LUA = """
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local cost = tonumber(ARGV[3])
local bucket = math.floor(now / window)
local elapsed = (now % window) / window

local current = {}
local previous = {}
for i, key in ipairs(KEYS) do
    local state = redis.call('HMGET', key, 'b', 'c', 'p')
    local b, c, p = tonumber(state[1]), tonumber(state[2]) or 0, tonumber(state[3]) or 0
    if b == nil or b < bucket - 1 then
        c, p = 0, 0
    elseif b == bucket - 1 then
        p, c = c, 0
    end
    current[i], previous[i] = c, p

    local limit = tonumber(ARGV[3 + i])
    if limit > 0 then
        local used = p * (1 - elapsed) + c
        if used + cost > limit then
            return {0, i}
        end
    end
end

for i, key in ipairs(KEYS) do
    redis.call('HSET', key, 'b', bucket, 'c', current[i] + cost, 'p', previous[i])
    redis.call('PEXPIRE', key, window * 2)
end
return {1, 0}
"""

# KEYS[i]  the same hashes as above
# ARGV[1]  signed token correction, added to each key's current bucket
# A key that no longer exists (idle for two windows) is left alone, and a count never
# goes below zero, so a late refund cannot create credit.
ADJUST_LUA = """
local delta = tonumber(ARGV[1])
for _, key in ipairs(KEYS) do
    if redis.call('EXISTS', key) == 1 then
        local c = tonumber(redis.call('HGET', key, 'c')) or 0
        redis.call('HSET', key, 'c', math.max(0, c + delta))
    end
end
return 1
"""


class SlidingWindowBudget:
    """Python side of the script: registers it once and calls it by hash."""

    def __init__(self, redis: Redis, *, window_s: int = 60) -> None:
        if window_s <= 0:
            raise ValueError("window_s must be positive")
        self.window_ms = window_s * 1000
        self._script: AsyncScript = redis.register_script(SLIDING_WINDOW_LUA)
        self._adjust: AsyncScript = redis.register_script(ADJUST_LUA)

    async def check_and_consume(
        self, keys: Sequence[str], limits: Sequence[int], cost: int, *, now_ms: int
    ) -> int | None:
        """Charge ``cost`` tokens to every key, or to none.

        Returns None when charged, else the 0-based index of the first dimension that
        had no room (so the caller can say which limit stopped the request).
        """
        if len(keys) != len(limits):
            raise ValueError("keys and limits must have the same length")
        if not keys:
            raise ValueError("at least one budget key is required")
        allowed, failed = await self._script(
            keys=list(keys), args=[now_ms, self.window_ms, cost, *limits]
        )
        return None if allowed else int(failed) - 1

    async def adjust(self, keys: Sequence[str], delta: int) -> None:
        """Add a signed correction to the current bucket of every key (never below 0)."""
        if keys and delta:
            await self._adjust(keys=list(keys), args=[delta])
