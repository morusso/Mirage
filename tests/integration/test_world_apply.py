"""WorldState.apply: validated updates land in the delta and show in snapshots."""

from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any
from uuid import uuid4

import pytest
from redis.asyncio import Redis

from app.engine.world import WorldState
from app.engine.world_data import USER_COUNT, base_user
from app.engine.world_delta import DELETED, FIRST_NEW_ID, DeltaStore, WorldStateUnavailable
from app.engine.world_updates import StateUpdate, parse_updates
from domain.captured_request import CapturedRequest

pytestmark = pytest.mark.integration

W = "w_0123456789abcdef"


def _req(path: str) -> CapturedRequest:
    return CapturedRequest(
        ts=datetime.now(UTC),
        session_id=uuid4(),
        world_id=W,
        ip=ip_address("203.0.113.9"),
        method="GET",
        path=path,
    )


@pytest.fixture
async def delta(redis: Redis) -> DeltaStore:
    await redis.flushdb()
    return DeltaStore(redis)


@pytest.fixture
def world(delta: DeltaStore) -> WorldState:
    return WorldState(delta)


def _update(**kw: Any) -> StateUpdate:
    return StateUpdate.model_validate(kw)


async def _user(world: WorldState, user_id: int) -> dict[str, Any] | None:
    snapshot = await world.snapshot_for(W, _req(f"/api/v1/users/{user_id}"))
    return snapshot["users"]["requested"][str(user_id)]  # type: ignore[no-any-return]


async def test_created_object_is_whole_and_visible_afterwards(world: WorldState) -> None:
    result = await world.apply(
        W,
        [_update(op="create", kind="users", id=1042, fields={"email": "eve@example.com"})],
    )

    user = await _user(world, 1042)
    assert (result.applied, result.rejected) == (1, ())
    assert user is not None
    assert (user["id"], user["email"]) == (1042, "eve@example.com")
    assert user["first_name"] and user["created_at"]  # the seed filled in the rest


async def test_create_without_an_id_gets_the_next_free_one(
    world: WorldState, delta: DeltaStore
) -> None:
    await delta.put(W, "users", FIRST_NEW_ID, {"id": FIRST_NEW_ID})  # taken explicitly

    await world.apply(W, [_update(op="create", kind="users")])

    assert await _user(world, FIRST_NEW_ID + 1) is not None
    assert await _user(world, FIRST_NEW_ID) == {"id": FIRST_NEW_ID}  # untouched


async def test_update_merges_into_the_base_object(world: WorldState) -> None:
    before = base_user(W, 5)
    assert before is not None

    await world.apply(W, [_update(op="update", kind="users", id=5, fields={"role": "admin"})])

    assert await _user(world, 5) == {**before.model_dump(), "role": "admin"}


async def test_delete_removes_the_object_for_good(world: WorldState) -> None:
    await world.apply(W, [_update(op="delete", kind="users", id=5)])

    assert await _user(world, 5) is None


async def test_updates_in_one_call_see_each_other(world: WorldState) -> None:
    result = await world.apply(
        W,
        [
            _update(op="create", kind="users", id=1500),
            _update(op="update", kind="users", id=1500, fields={"role": "admin"}),
            _update(op="delete", kind="users", id=1500),
        ],
    )

    assert result.applied == 3
    assert await _user(world, 1500) is None


@pytest.mark.parametrize(
    ("update", "reason"),
    [
        ({"op": "update", "kind": "users", "id": 5, "fields": {"nope": 1}}, "unknown field"),
        ({"op": "update", "kind": "users", "id": 5, "fields": {"id": 6}}, "unknown field"),
        ({"op": "update", "kind": "users", "id": 9999}, "no such object"),
        ({"op": "delete", "kind": "users", "id": 9999}, "no such object"),
        ({"op": "create", "kind": "users", "id": 5}, "id exists"),
        (
            {"op": "update", "kind": "products", "id": 3, "fields": {"price": "cheap"}},
            "invalid value",
        ),
        ({"op": "update", "kind": "products", "id": 3, "fields": {"stock": None}}, "invalid value"),
    ],
)
async def test_unfit_updates_are_rejected_and_change_nothing(
    world: WorldState, delta: DeltaStore, update: dict[str, Any], reason: str
) -> None:
    result = await world.apply(W, [_update(**update)])

    assert result.applied == 0
    assert len(result.rejected) == 1 and reason in result.rejected[0]
    assert await delta.all(W, "users") == {}
    assert await delta.all(W, "products") == {}


async def test_a_rejected_update_does_not_stop_the_rest(world: WorldState) -> None:
    result = await world.apply(
        W,
        [
            _update(op="update", kind="users", id=9999),
            _update(op="update", kind="users", id=5, fields={"role": "admin"}),
        ],
    )

    assert result.applied == 1
    assert len(result.rejected) == 1
    user = await _user(world, 5)
    assert user is not None and user["role"] == "admin"


async def test_a_deleted_base_id_can_be_created_again(world: WorldState, delta: DeltaStore) -> None:
    await delta.delete(W, "users", 5)

    result = await world.apply(
        W, [_update(op="create", kind="users", id=5, fields={"email": "back@example.com"})]
    )

    user = await _user(world, 5)
    assert result.applied == 1
    assert user is not None and user["email"] == "back@example.com"


async def test_model_output_flows_through_parse_and_apply(world: WorldState) -> None:
    raw = [
        {"op": "create", "kind": "products", "id": 2001, "fields": {"name": "Gift Card"}},
        {"op": "drop_tables", "kind": "users"},
    ]

    result = await world.apply(W, parse_updates(raw))

    snapshot = await world.snapshot_for(W, _req("/api/v1/products/2001"))
    assert result.applied == 1
    assert snapshot["products"]["requested"]["2001"]["name"] == "Gift Card"


async def test_totals_follow_applied_updates(world: WorldState) -> None:
    await world.apply(
        W,
        [_update(op="create", kind="users", id=1042), _update(op="delete", kind="users", id=1)],
    )

    users = (await world.snapshot_for(W, _req("/api/v1/users")))["users"]
    assert users["total"] == USER_COUNT


async def test_deleting_something_created_leaves_a_tombstone(
    world: WorldState, delta: DeltaStore
) -> None:
    await world.apply(
        W,
        [_update(op="create", kind="users", id=1042), _update(op="delete", kind="users", id=1042)],
    )

    assert await delta.get(W, "users", 1042) is DELETED


async def test_unreachable_redis_raises() -> None:
    dead = Redis.from_url("redis://127.0.0.1:1/0", decode_responses=True)

    with pytest.raises(WorldStateUnavailable):
        await WorldState(DeltaStore(dead)).apply(W, [_update(op="create", kind="users")])
    await dead.aclose()
