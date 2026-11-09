"""DeltaStore against a real Redis."""

import pytest
from redis.asyncio import Redis

from app.engine.world_delta import (
    DELETED,
    FIRST_NEW_ID,
    MAX_OBJECT_BYTES,
    MAX_OBJECTS_PER_KIND,
    DeltaStore,
    WorldFull,
    WorldStateUnavailable,
)

pytestmark = pytest.mark.integration

W = "w_aaaa"
USER = {"id": 1042, "email": "x@example.com", "role": "customer"}


@pytest.fixture
async def store(redis: Redis) -> DeltaStore:
    await redis.flushdb()  # the redis fixture is shared and world ids repeat across tests
    return DeltaStore(redis)


async def test_untouched_object_is_absent(store: DeltaStore) -> None:
    assert await store.get(W, "users", 7) is None


async def test_put_then_get_round_trips(store: DeltaStore) -> None:
    await store.put(W, "users", 1042, USER)

    assert await store.get(W, "users", 1042) == USER


async def test_put_replaces_an_existing_object(store: DeltaStore) -> None:
    await store.put(W, "users", 1042, USER)
    await store.put(W, "users", 1042, {**USER, "role": "admin"})

    assert await store.get(W, "users", 1042) == {**USER, "role": "admin"}


async def test_delete_leaves_a_tombstone_not_an_absence(store: DeltaStore) -> None:
    await store.delete(W, "users", 3)  # a base user: the seed alone would bring it back

    assert await store.get(W, "users", 3) is DELETED


async def test_a_deleted_object_can_be_recreated(store: DeltaStore) -> None:
    await store.delete(W, "users", 3)
    await store.put(W, "users", 3, USER)

    assert await store.get(W, "users", 3) == USER


async def test_worlds_and_kinds_are_isolated(store: DeltaStore) -> None:
    await store.put(W, "users", 1, USER)

    assert await store.get("w_bbbb", "users", 1) is None
    assert await store.get(W, "products", 1) is None


async def test_all_lists_every_touched_object(store: DeltaStore) -> None:
    await store.put(W, "users", 1001, USER)
    await store.delete(W, "users", 5)

    assert await store.all(W, "users") == {1001: USER, 5: DELETED}
    assert await store.all(W, "products") == {}


async def test_next_id_counts_from_the_first_new_id_per_world_and_kind(
    store: DeltaStore,
) -> None:
    ids = [await store.next_id(W, "users") for _ in range(3)]

    assert ids == [FIRST_NEW_ID, FIRST_NEW_ID + 1, FIRST_NEW_ID + 2]
    assert await store.next_id(W, "products") == FIRST_NEW_ID
    assert await store.next_id("w_bbbb", "users") == FIRST_NEW_ID


async def test_a_world_expires_and_every_write_extends_it(redis: Redis) -> None:
    await redis.flushdb()
    store = DeltaStore(redis, ttl_s=100)
    key = f"mirage:world:{W}:users"

    await store.put(W, "users", 1, USER)
    await redis.expire(key, 5)  # pretend most of the lifetime has passed
    await store.put(W, "users", 2, USER)

    assert 5 < await redis.ttl(key) <= 100


async def test_counter_also_expires(redis: Redis) -> None:
    await redis.flushdb()
    store = DeltaStore(redis, ttl_s=100)

    await store.next_id(W, "users")

    assert 0 < await redis.ttl(f"mirage:world:{W}#seq") <= 100


async def test_objects_per_kind_are_capped_but_existing_ones_stay_writable(
    redis: Redis,
) -> None:
    await redis.flushdb()
    store = DeltaStore(redis)
    key = f"mirage:world:{W}:users"
    await redis.hset(key, mapping={str(i): "{}" for i in range(MAX_OBJECTS_PER_KIND)})

    with pytest.raises(WorldFull):
        await store.put(W, "users", 99_999, USER)
    await store.put(W, "users", 0, USER)  # an update of an existing field is not growth

    assert await redis.hlen(key) == MAX_OBJECTS_PER_KIND


async def test_oversized_object_is_rejected(store: DeltaStore) -> None:
    with pytest.raises(ValueError, match="too large"):
        await store.put(W, "users", 1, {"bio": "x" * MAX_OBJECT_BYTES})


@pytest.mark.parametrize("kind", ["", "Users", "users:x", "../x", "a" * 33, "1users"])
async def test_invalid_kind_is_rejected(store: DeltaStore, kind: str) -> None:
    with pytest.raises(ValueError, match="invalid kind"):
        await store.get(W, kind, 1)


async def test_unreachable_redis_raises_world_state_unavailable() -> None:
    dead = Redis.from_url("redis://127.0.0.1:1/0", decode_responses=True)
    store = DeltaStore(dead)

    with pytest.raises(WorldStateUnavailable):
        await store.get(W, "users", 1)
    with pytest.raises(WorldStateUnavailable):
        await store.put(W, "users", 1, USER)
    with pytest.raises(WorldStateUnavailable):
        await store.next_id(W, "users")
    await dead.aclose()
