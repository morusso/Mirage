from datetime import UTC, datetime
from ipaddress import ip_address
from uuid import uuid4

import pytest

from app.engine.signature import normalize_path, normalize_query, request_signature
from domain.captured_request import CapturedRequest


def _req(**kw: object) -> CapturedRequest:
    base: dict[str, object] = {
        "ts": datetime(2026, 1, 1, tzinfo=UTC),
        "session_id": uuid4(),
        "world_id": "w_x",
        "persona": "fake_api",
        "ip": ip_address("203.0.113.1"),
        "method": "GET",
        "path": "/api/v1/products",
    }
    return CapturedRequest(**{**base, **kw})  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("/a/b", "/a/b"),
        ("/a/b/", "/a/b"),
        ("//a///b", "/a/b"),
        ("", "/"),
        ("/", "/"),
        ("a/b", "/a/b"),
        ("/A/b", "/A/b"),  # case is kept
        ("/a/../b", "/a/../b"),  # traversal is payload, not folded
    ],
)
def test_normalize_path(raw: str, expected: str) -> None:
    assert normalize_path(raw) == expected


def test_normalize_query_sorts_and_drops_cache_busters() -> None:
    assert normalize_query("b=2&a=1&_=123&TS=9&cb=x") == "a=1&b=2"
    assert normalize_query("a=&b") == "a=&b="
    assert normalize_query("") == ""


def test_equivalent_requests_share_a_signature() -> None:
    a = _req(path="/api/v1/products/", query="page=2&limit=5&_=1")
    b = _req(path="//api/v1/products", query="limit=5&page=2&_=2")

    assert request_signature(a) == request_signature(b)


def test_ip_session_and_headers_do_not_matter() -> None:
    a = _req(ip=ip_address("203.0.113.1"), headers=[("user-agent", "a")])
    b = _req(ip=ip_address("198.51.100.7"), headers=[("user-agent", "b")])

    assert request_signature(a) == request_signature(b)


@pytest.mark.parametrize(
    "change",
    [
        {"persona": "wordpress"},
        {"method": "POST"},
        {"path": "/api/v1/users"},
        {"query": "page=3"},
    ],
)
def test_relevant_differences_change_the_signature(change: dict[str, str]) -> None:
    assert request_signature(_req()) != request_signature(_req(**change))


def test_missing_persona_differs_from_a_named_one() -> None:
    assert request_signature(_req(persona=None)) != request_signature(_req())


def test_scope_partitions_the_cache() -> None:
    req = _req()

    assert request_signature(req, scope="w_1") != request_signature(req, scope="w_2")
    assert request_signature(req, scope="w_1") == request_signature(req, scope="w_1")


def test_body_hash_matters_for_posts_but_not_gets() -> None:
    h1, h2 = "a" * 64, "b" * 64

    assert request_signature(_req(method="POST", body_sha256=h1)) != request_signature(
        _req(method="POST", body_sha256=h2)
    )
    assert request_signature(_req(method="get", body_sha256=h1)) == request_signature(
        _req(method="GET", body_sha256=h2)
    )


def test_fields_cannot_be_shifted_across_separators() -> None:
    a = _req(path="/a", query="b=1")
    b = _req(path="/a?b=1", query="")

    assert request_signature(a) != request_signature(b)
