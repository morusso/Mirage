from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from pydantic import ValidationError

from domain.captured_request import CapturedRequest

SHA = "a" * 64


def _make(**overrides: Any) -> CapturedRequest:
    data: dict[str, Any] = {
        "ts": datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
        "session_id": uuid4(),
        "world_id": "w_abc",
        "ip": "203.0.113.17",
        "method": "GET",
        "path": "/api/v1/users/1",
    }
    return CapturedRequest(**{**data, **overrides})


def test_minimal_request_has_defaults() -> None:
    req = _make()

    assert req.query == ""
    assert req.headers == []
    assert req.body_excerpt == ""
    assert req.body_truncated is False
    assert (req.tier, req.status, req.latency_ms, req.tokens_used) == (None, None, None, None)


def test_event_ids_are_unique() -> None:
    assert _make().event_id != _make().event_id


def test_accepts_ipv4_and_ipv6() -> None:
    assert str(_make(ip="2001:db8::1").ip) == "2001:db8::1"
    assert str(_make(ip="203.0.113.17").ip) == "203.0.113.17"


def test_headers_keep_order_and_duplicates() -> None:
    headers = [("Host", "a"), ("X-Forwarded-For", "1.1.1.1"), ("X-Forwarded-For", "2.2.2.2")]

    assert _make(headers=headers).headers == headers


@pytest.mark.parametrize(
    "overrides",
    [
        {"ip": "not-an-ip"},
        {"ts": datetime(2026, 1, 1)},
        {"port": 70000},
        {"body_sha256": "xyz"},
        {"body_size": -1},
        {"tier": 3},
        {"status": 99},
        {"unexpected": 1},
    ],
)
def test_rejects_invalid_values(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        _make(**overrides)


def test_model_is_immutable() -> None:
    req = _make()

    with pytest.raises(ValidationError):
        req.path = "/other"


def test_with_response_returns_updated_copy() -> None:
    req = _make()

    done = req.with_response(tier=1, status=200, latency_ms=412, tokens_used=180)

    assert (done.tier, done.status, done.latency_ms, done.tokens_used) == (1, 200, 412, 180)
    assert done.event_id == req.event_id
    assert req.status is None


def test_json_roundtrip_preserves_event() -> None:
    req = _make(
        headers=[("A", "b")], body_sha256=SHA, port=51234, ja4="t13d1516h2_8daaf6152771"
    ).with_response(tier=0, status=404, latency_ms=3)

    assert CapturedRequest.model_validate_json(req.model_dump_json()) == req
