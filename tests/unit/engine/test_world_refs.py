import json
from datetime import UTC, datetime
from ipaddress import ip_address
from uuid import uuid4

import pytest

from app.engine.world import MAX_REFERENCED_IDS, path_kinds, referenced_ids
from domain.captured_request import CapturedRequest


def _req(
    path: str = "/", query: str = "", body: object | str | None = None, method: str = "GET"
) -> CapturedRequest:
    excerpt = body if isinstance(body, str) else (json.dumps(body) if body is not None else "")
    return CapturedRequest(
        ts=datetime.now(UTC),
        session_id=uuid4(),
        world_id="w",
        ip=ip_address("203.0.113.9"),
        method=method,
        path=path,
        query=query,
        body_excerpt=excerpt,
    )


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/api/v1/users/1042", {"users": [1042]}),
        ("/api/v1/users/1042/", {"users": [1042]}),
        ("//api/v1//products/7", {"products": [7]}),
        ("/api/v1/users/5/orders/9", {"users": [5]}),
        ("/api/v1/users", {}),
        ("/api/v1/users/abc", {}),
        ("/api/v1/users/-3", {}),
        ("/api/v1/users/0", {}),
        ("/api/v1/users/1e3", {}),
        ("/api/v1/users/12345678901234567890", {}),
        ("/api/v1/users/١٢٣", {}),  # non-ASCII digits are not ids
        ("/other/users/5", {"users": [5]}),
    ],
)
def test_ids_from_the_path(path: str, expected: dict[str, list[int]]) -> None:
    assert referenced_ids(_req(path)) == expected


def test_ids_from_query_parameters() -> None:
    assert referenced_ids(_req("/api/v1/orders", "user_id=5&productId=9&x=1")) == {
        "users": [5],
        "products": [9],
    }


def test_bare_id_belongs_to_the_kind_in_the_path_only() -> None:
    assert referenced_ids(_req("/api/v1/users", "id=5")) == {"users": [5]}
    assert referenced_ids(_req("/api/v1/orders", "id=5")) == {}


def test_ids_from_a_json_body_including_list_items() -> None:
    body = {"user_id": 3, "items": [{"product_id": "8"}, {"product_id": 9}, "junk", 4]}

    assert referenced_ids(_req("/api/v1/orders", body=body, method="POST")) == {
        "users": [3],
        "products": [8, 9],
    }


def test_truncated_or_invalid_json_body_is_ignored() -> None:
    assert referenced_ids(_req("/x", body='{"user_id": 3, "pad": "xxxx')) == {}
    assert referenced_ids(_req("/x", body="[1, 2]")) == {}
    assert referenced_ids(_req("/x", body='"user_id"')) == {}


def test_booleans_and_floats_are_not_ids() -> None:
    assert referenced_ids(_req("/x", body={"user_id": True, "product_id": 2.5})) == {}


def test_duplicates_collapse_and_order_is_kept() -> None:
    assert referenced_ids(_req("/api/v1/users/7", "user_id=3&user_id=7&userId=3")) == {
        "users": [7, 3]
    }


def test_number_of_ids_is_capped() -> None:
    query = "&".join(f"user_id={i}" for i in range(1, 100))

    assert len(referenced_ids(_req("/x", query))["users"]) == MAX_REFERENCED_IDS


def test_path_kinds_names_collections_and_objects() -> None:
    assert path_kinds(_req("/api/v1/users")) == {"users"}
    assert path_kinds(_req("/api/v1/products/3")) == {"products"}
    assert path_kinds(_req("/api/v1/orders")) == set()
