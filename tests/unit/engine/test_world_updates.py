import pytest
from pydantic import ValidationError

from app.engine.world_updates import (
    MAX_FIELDS,
    MAX_TEXT_CHARS,
    MAX_UPDATES,
    StateUpdate,
    parse_updates,
)


def test_valid_operations() -> None:
    assert StateUpdate(op="create", kind="users", fields={"email": "a@example.com"}).id is None
    assert StateUpdate(op="update", kind="products", id=3, fields={"stock": 0}).id == 3
    assert StateUpdate(op="delete", kind="users", id=1001).fields == {}


@pytest.mark.parametrize(
    "bad",
    [
        {"op": "drop", "kind": "users", "id": 1},
        {"op": "update", "kind": "orders", "id": 1},
        {"op": "update", "kind": "users"},  # no id
        {"op": "delete", "kind": "users"},
        {"op": "delete", "kind": "users", "id": 1, "fields": {"role": "x"}},
        {"op": "update", "kind": "users", "id": 0},
        {"op": "update", "kind": "users", "id": -5},
        {"op": "update", "kind": "users", "id": 10**9},
        {"op": "update", "kind": "users", "id": 1, "extra": "x"},
        {"op": "update", "kind": "users", "id": 1, "fields": {"a": {"nested": 1}}},
        {"op": "update", "kind": "users", "id": 1, "fields": {"a": [1]}},
        {"op": "update", "kind": "users", "id": 1, "fields": {"a": "x" * (MAX_TEXT_CHARS + 1)}},
        {"op": "update", "kind": "users", "id": 1, "fields": {"k" * 65: 1}},
        {
            "op": "update",
            "kind": "users",
            "id": 1,
            "fields": {f"f{i}": 1 for i in range(MAX_FIELDS + 1)},
        },
    ],
)
def test_malformed_updates_are_rejected(bad: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        StateUpdate.model_validate(bad)


def test_parse_keeps_good_updates_and_drops_bad_ones() -> None:
    raw = [
        {"op": "delete", "kind": "users", "id": 5},
        {"op": "explode"},
        "junk",
        None,
        {"op": "update", "kind": "products", "id": 2, "fields": {"stock": 1}},
    ]

    assert [u.op for u in parse_updates(raw)] == ["delete", "update"]


@pytest.mark.parametrize("raw", [None, {}, "x", 5, {"op": "delete"}])
def test_parse_of_a_non_list_is_empty(raw: object) -> None:
    assert parse_updates(raw) == []


def test_parse_caps_the_number_of_updates() -> None:
    raw = [{"op": "delete", "kind": "users", "id": i} for i in range(1, 100)]

    assert len(parse_updates(raw)) == MAX_UPDATES
