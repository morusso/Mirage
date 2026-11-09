"""WorldState.snapshot_for: seed and delta merged, cut down to the request."""

from datetime import UTC, datetime
from ipaddress import ip_address
from uuid import uuid4

import pytest
from redis.asyncio import Redis

from app.engine.world import SAMPLE_SIZE, WorldState
from app.engine.world_data import USER_COUNT, base_user
from app.engine.world_delta import DeltaStore, WorldStateUnavailable
from domain.captured_request import CapturedRequest

pytestmark = pytest.mark.integration

W = "w_0123456789abcdef"
NEW_USER = {"id": 1001, "email": "new@example.com", "role": "customer"}


def _req(path: str, query: str = "", body: str = "") -> CapturedRequest:
    return CapturedRequest(
        ts=datetime.now(UTC),
        session_id=uuid4(),
        world_id=W,
        ip=ip_address("203.0.113.9"),
        method="GET",
        path=path,
        query=query,
        body_excerpt=body,
    )


@pytest.fixture
async def delta(redis: Redis) -> DeltaStore:
    await redis.flushdb()
    return DeltaStore(redis)


@pytest.fixture
def world(delta: DeltaStore) -> WorldState:
    return WorldState(delta)


async def test_untouched_base_object_comes_from_the_seed(world: WorldState) -> None:
    expected = base_user(W, 5)
    assert expected is not None

    snapshot = await world.snapshot_for(W, _req("/api/v1/users/5"))

    assert snapshot["users"]["requested"] == {"5": expected.model_dump()}


async def test_created_object_is_visible(world: WorldState, delta: DeltaStore) -> None:
    await delta.put(W, "users", 1001, NEW_USER)

    snapshot = await world.snapshot_for(W, _req("/api/v1/users/1001"))

    assert snapshot["users"]["requested"] == {"1001": NEW_USER}


async def test_modified_base_object_shows_the_attackers_version(
    world: WorldState, delta: DeltaStore
) -> None:
    await delta.put(W, "users", 5, {"id": 5, "role": "admin"})

    snapshot = await world.snapshot_for(W, _req("/api/v1/users/5"))

    assert snapshot["users"]["requested"] == {"5": {"id": 5, "role": "admin"}}


async def test_deleted_and_never_existing_objects_are_null(
    world: WorldState, delta: DeltaStore
) -> None:
    await delta.delete(W, "users", 5)

    snapshot = await world.snapshot_for(W, _req("/api/v1/users/5", "user_id=7777"))

    assert snapshot["users"]["requested"] == {"5": None, "7777": None}


async def test_collection_request_gets_total_and_a_sample(world: WorldState) -> None:
    snapshot = await world.snapshot_for(W, _req("/api/v1/users"))

    users = snapshot["users"]
    assert users["total"] == USER_COUNT
    assert [u["id"] for u in users["sample"]] == list(range(1, SAMPLE_SIZE + 1))
    assert "requested" not in users


async def test_total_and_sample_follow_creations_and_deletions(
    world: WorldState, delta: DeltaStore
) -> None:
    await delta.put(W, "users", 1001, NEW_USER)
    await delta.delete(W, "users", 1)  # a base user
    await delta.delete(W, "users", 2002)  # deleting something that never existed: no effect
    await delta.put(W, "users", 2, {"id": 2, "role": "admin"})  # a change is not growth

    users = (await world.snapshot_for(W, _req("/api/v1/users")))["users"]

    assert users["total"] == USER_COUNT  # +1 created, -1 deleted
    assert users["sample"][0] == {"id": 2, "role": "admin"}


async def test_only_relevant_kinds_appear(world: WorldState) -> None:
    snapshot = await world.snapshot_for(W, _req("/api/v1/products/3"))

    assert set(snapshot) == {"products"}
    assert set(snapshot["products"]) == {"requested", "total", "sample"}


async def test_unrelated_request_has_an_empty_snapshot(world: WorldState) -> None:
    assert await world.snapshot_for(W, _req("/api/v1/orders")) == {}


async def test_body_references_are_resolved(world: WorldState, delta: DeltaStore) -> None:
    await delta.put(W, "users", 1001, NEW_USER)

    snapshot = await world.snapshot_for(W, _req("/api/v1/orders", body='{"user_id": 1001}'))

    assert snapshot == {"users": {"requested": {"1001": NEW_USER}}}


async def test_worlds_do_not_see_each_others_changes(world: WorldState, delta: DeltaStore) -> None:
    await delta.put("w_other", "users", 1001, NEW_USER)

    snapshot = await world.snapshot_for(W, _req("/api/v1/users/1001"))

    assert snapshot["users"]["requested"] == {"1001": None}


async def test_unreachable_redis_raises() -> None:
    dead = Redis.from_url("redis://127.0.0.1:1/0", decode_responses=True)

    with pytest.raises(WorldStateUnavailable):
        await WorldState(DeltaStore(dead)).snapshot_for(W, _req("/api/v1/users/1"))
    await dead.aclose()
