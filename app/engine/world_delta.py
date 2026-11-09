"""The delta of a world: what the attacker created, changed or deleted.

The base world is generated from a seed (see ``world_data``); only differences from it
are stored, in one Redis hash per world and kind::

    mirage:world:<world_id>:<kind>   field = object id, value = JSON object
                                     or ``null`` (a tombstone: the object was deleted)

A tombstone matters: a deleted base user must stay gone, and "absent from the delta"
would let the seed bring it back. Every write refreshes the world's TTL, so a world
lives as long as its attacker keeps coming back and then disappears.

Writes are bounded, because the attacker controls them: at most ``MAX_OBJECTS_PER_KIND``
per kind and ``MAX_OBJECT_BYTES`` per object, so a loop of POSTs cannot fill Redis.
"""

import asyncio
import json
import re
from enum import Enum
from typing import Any

from redis.asyncio import Redis
from redis.exceptions import RedisError

KEY_PREFIX = "mirage:world:"
DEFAULT_TTL_S = 7 * 24 * 3600
MAX_OBJECTS_PER_KIND = 1000
MAX_OBJECT_BYTES = 8 * 1024
# First id handed to a created object: clear of the base ids (1..USER_COUNT).
FIRST_NEW_ID = 1001

_NAME = re.compile(r"^[a-z][a-z_]{0,31}$")

# KEYS[1] hash, ARGV: field, value, max objects, ttl seconds.
# Returns 1 when written, 0 when the hash is full and the field is new.
_PUT_LUA = """
if redis.call('HEXISTS', KEYS[1], ARGV[1]) == 0
   and redis.call('HLEN', KEYS[1]) >= tonumber(ARGV[3]) then
    return 0
end
redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[4]))
return 1
"""


class _Deleted(Enum):
    MARK = "deleted"


# What ``get`` returns for an object the attacker deleted.
DELETED = _Deleted.MARK

Entry = dict[str, Any] | _Deleted


class WorldStateUnavailable(Exception):
    """Redis could not answer in time. The caller falls back to tier 0."""


class WorldFull(Exception):
    """The attacker already created the maximum number of objects of this kind."""


def _check_kind(kind: str) -> None:
    if not _NAME.fullmatch(kind):
        raise ValueError(f"invalid kind {kind!r}")


class DeltaStore:
    def __init__(self, redis: Redis, *, ttl_s: int = DEFAULT_TTL_S, timeout_s: float = 0.2) -> None:
        self.redis = redis
        self.ttl_s = ttl_s
        self.timeout_s = timeout_s
        self._put = redis.register_script(_PUT_LUA)

    @staticmethod
    def _key(world_id: str, kind: str) -> str:
        _check_kind(kind)
        return f"{KEY_PREFIX}{world_id}:{kind}"

    async def get(self, world_id: str, kind: str, object_id: int) -> Entry | None:
        """The stored object, ``DELETED``, or None if the attacker never touched it."""
        raw = await self._call(self.redis.hget(self._key(world_id, kind), str(object_id)))
        return None if raw is None else _decode(raw)

    async def all(self, world_id: str, kind: str) -> dict[int, Entry]:
        """Every touched object of a kind, by id."""
        raw = await self._call(self.redis.hgetall(self._key(world_id, kind)))
        return {int(field): _decode(value) for field, value in raw.items()}

    async def put(self, world_id: str, kind: str, object_id: int, data: dict[str, Any]) -> None:
        """Create or replace an object. Raises ``WorldFull`` at the per-kind cap."""
        encoded = json.dumps(data, separators=(",", ":"), sort_keys=True)
        if len(encoded.encode()) > MAX_OBJECT_BYTES:
            raise ValueError("object too large")
        await self._store(world_id, kind, object_id, encoded)

    async def delete(self, world_id: str, kind: str, object_id: int) -> None:
        """Mark an object deleted (also for base objects, which the seed would revive)."""
        await self._store(world_id, kind, object_id, "null")

    async def next_id(self, world_id: str, kind: str) -> int:
        """Id for a new object: FIRST_NEW_ID, then one more each call, per world and kind."""
        _check_kind(kind)
        # "#" cannot appear in a kind, so a counter never collides with an object hash.
        key = f"{KEY_PREFIX}{world_id}#seq"
        count = await self._call(self._increment(key, kind))
        return FIRST_NEW_ID + int(count) - 1

    async def peek_seq(self, world_id: str, kind: str) -> int:
        """How many ids ``next_id`` has handed out so far for this world and kind."""
        _check_kind(kind)
        raw = await self._call(self.redis.hget(f"{KEY_PREFIX}{world_id}#seq", kind))
        return int(raw) if raw is not None else 0

    async def _increment(self, key: str, kind: str) -> int:
        count = await self.redis.hincrby(key, kind, 1)
        await self.redis.expire(key, self.ttl_s)
        return int(count)

    async def _store(self, world_id: str, kind: str, object_id: int, encoded: str) -> None:
        written = await self._call(
            self._put(
                keys=[self._key(world_id, kind)],
                args=[str(object_id), encoded, MAX_OBJECTS_PER_KIND, self.ttl_s],
            )
        )
        if not written:
            raise WorldFull(kind)

    async def _call(self, awaitable: Any) -> Any:
        try:
            async with asyncio.timeout(self.timeout_s):
                return await awaitable
        except (RedisError, OSError, TimeoutError) as exc:
            raise WorldStateUnavailable(type(exc).__name__) from exc


def _decode(raw: str) -> Entry:
    value: dict[str, Any] | None = json.loads(raw)
    return DELETED if value is None else value
