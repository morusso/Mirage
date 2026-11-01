import asyncio
import hashlib
from ipaddress import ip_network
from typing import Any

import pytest

from app.asgi_types import Message, Receive, Scope, Send
from app.capture.middleware import CaptureMiddleware
from app.personas.base import PERSONA_SCOPE_KEY, PersonaConfig
from domain.captured_request import CapturedRequest


def _scope(**overrides: Any) -> Scope:
    scope: Scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/auth/login",
        "raw_path": b"/api/v1/auth/login",
        "query_string": b"a=1&b=2",
        "headers": [(b"host", b"shop.test"), (b"x-dup", b"1"), (b"x-dup", b"2")],
        "client": ("203.0.113.17", 51234),
    }
    scope.update(overrides)
    return scope


class _Harness:
    """Runs the middleware with a scripted request and records what happens."""

    def __init__(
        self, *, max_excerpt: int = 1024, max_read: int = 1024 * 1024, trusted: bool = False
    ) -> None:
        self.trusted = [ip_network("10.0.0.0/8")] if trusted else []
        self.events: list[CapturedRequest] = []
        self.order: list[str] = []
        self.app_messages: list[Message] = []
        self.sent: list[Message] = []
        self.status = 200
        self.raises: Exception | None = None
        self.send_response = True
        self.scope_updates: dict[str, Any] = {}
        self.app_delay_s = 0.0
        self.max_excerpt = max_excerpt
        self.max_read = max_read

    async def _sink(self, event: CapturedRequest) -> None:
        self.order.append("sink")
        self.events.append(event)

    async def _app(self, scope: Scope, receive: Receive, send: Send) -> None:
        self.order.append("app")
        # Read until the body ends or the client goes away, like a real handler.
        while True:
            message = await receive()
            self.app_messages.append(message)
            if message["type"] == "http.disconnect" or not message.get("more_body", False):
                break
        scope.update(self.scope_updates)
        await asyncio.sleep(self.app_delay_s)
        if self.raises:
            raise self.raises
        if self.send_response:
            await send({"type": "http.response.start", "status": self.status, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

    async def run(self, scope: Scope, messages: list[Message]) -> None:
        queue = list(messages)

        async def receive() -> Message:
            return queue.pop(0) if queue else {"type": "http.disconnect"}

        async def send(message: Message) -> None:
            self.sent.append(message)

        mw = CaptureMiddleware(
            self._app,
            self._sink,
            max_body_excerpt=self.max_excerpt,
            max_body_read=self.max_read,
            trusted_proxies=self.trusted,
        )
        await mw(scope, receive, send)

    @property
    def event(self) -> CapturedRequest:
        assert len(self.events) == 1
        return self.events[0]

    @property
    def app_body(self) -> bytes:
        return b"".join(
            m.get("body", b"") for m in self.app_messages if m["type"] == "http.request"
        )


def _body(data: bytes, *, more: bool = False) -> Message:
    return {"type": "http.request", "body": data, "more_body": more}


async def test_captures_request_metadata() -> None:
    h = _Harness()

    await h.run(_scope(), [_body(b'{"email":"a"}')])

    e = h.event
    assert (e.method, e.path, e.query) == ("POST", "/api/v1/auth/login", "a=1&b=2")
    assert (str(e.ip), e.port) == ("203.0.113.17", 51234)
    assert e.headers == [("host", "shop.test"), ("x-dup", "1"), ("x-dup", "2")]
    assert e.body_excerpt == '{"email":"a"}'
    assert e.body_size == 13
    assert e.body_sha256 == hashlib.sha256(b'{"email":"a"}').hexdigest()
    assert e.body_truncated is False


async def test_event_is_published_after_the_response() -> None:
    h = _Harness()

    await h.run(_scope(), [_body(b"x")])

    assert h.order == ["app", "sink"]
    assert [m["type"] for m in h.sent] == ["http.response.start", "http.response.body"]


async def test_response_metadata_is_recorded() -> None:
    h = _Harness()
    h.status = 418
    h.app_delay_s = 0.02

    await h.run(_scope(), [_body(b"")])

    e = h.event
    assert e.status == 418
    assert e.latency_ms is not None and e.latency_ms >= 20
    assert (e.tier, e.tokens_used) == (0, 0)


async def test_tier_and_tokens_are_read_from_scope() -> None:
    h = _Harness()
    h.scope_updates = {"mirage.tier": 1, "mirage.tokens_used": 180}

    await h.run(_scope(), [_body(b"")])

    assert (h.event.tier, h.event.tokens_used) == (1, 180)


async def test_persona_name_is_recorded() -> None:
    h = _Harness()
    h.scope_updates = {PERSONA_SCOPE_KEY: PersonaConfig(name="fake_api", server="nginx")}

    await h.run(_scope(), [_body(b"")])

    assert h.event.persona == "fake_api"


async def test_persona_is_none_when_no_router_claimed_the_request() -> None:
    h = _Harness()

    await h.run(_scope(), [_body(b"")])

    assert h.event.persona is None


async def test_crashing_app_is_recorded_as_500_and_error_propagates() -> None:
    h = _Harness()
    h.raises = RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        await h.run(_scope(), [_body(b"")])

    assert h.event.status == 500
    assert h.order == ["app", "sink"]


async def test_crash_after_response_started_keeps_the_sent_status() -> None:
    h = _Harness()

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        raise RuntimeError("late")

    mw = CaptureMiddleware(app, h._sink)

    async def receive() -> Message:
        return _body(b"")

    async def send(message: Message) -> None:
        return None

    with pytest.raises(RuntimeError):
        await mw(_scope(), receive, send)

    assert h.event.status == 200


async def test_response_that_never_starts_has_no_status() -> None:
    h = _Harness()
    h.send_response = False

    await h.run(_scope(), [_body(b"")])

    assert h.event.status is None


async def test_raw_path_is_kept_without_decoding() -> None:
    h = _Harness()

    await h.run(_scope(path="/../etc/passwd", raw_path=b"/%2e%2e/etc/passwd"), [_body(b"")])

    assert h.event.path == "/%2e%2e/etc/passwd"


async def test_downstream_app_receives_the_same_body() -> None:
    h = _Harness()

    await h.run(_scope(), [_body(b"abc", more=True), _body(b"def")])

    assert h.app_body == b"abcdef"
    assert h.event.body_excerpt == "abcdef"


async def test_empty_body_has_no_hash() -> None:
    h = _Harness()

    await h.run(_scope(method="GET"), [_body(b"")])

    assert (h.event.body_size, h.event.body_sha256, h.event.body_truncated) == (0, None, False)


async def test_large_body_is_hashed_in_full_but_excerpt_is_capped() -> None:
    h = _Harness(max_excerpt=10)
    data = b"0123456789ABCDEFGHIJ"

    await h.run(_scope(), [_body(data[:7], more=True), _body(data[7:])])

    e = h.event
    assert e.body_excerpt == "0123456789"
    assert e.body_size == 20
    assert e.body_sha256 == hashlib.sha256(data).hexdigest()
    assert e.body_truncated is True
    assert h.app_body == b"0123456789"


async def test_reading_stops_at_hard_limit_and_flags_truncation() -> None:
    h = _Harness(max_excerpt=4, max_read=8)
    chunks = [_body(b"aaaa", more=True), _body(b"bbbb", more=True), _body(b"cccc", more=True)]

    await h.run(_scope(), chunks)

    assert h.event.body_size == 8
    assert h.event.body_truncated is True
    # The abandoned remainder is never leaked to the app as body data.
    assert h.app_body == b"aaaa"


async def test_client_disconnect_while_sending_body() -> None:
    h = _Harness()

    await h.run(_scope(), [_body(b"par", more=True), {"type": "http.disconnect"}])

    assert h.event.body_excerpt == "par"
    assert h.app_messages == [{"type": "http.disconnect"}]


async def test_binary_body_does_not_break_capture() -> None:
    h = _Harness()

    await h.run(_scope(), [_body(b"\xff\xfe\x00bin")])

    assert "bin" in h.event.body_excerpt
    assert h.event.body_size == 6


async def test_missing_client_falls_back_to_unspecified_address() -> None:
    h = _Harness()

    await h.run(_scope(client=None), [_body(b"")])

    assert (str(h.event.ip), h.event.port) == ("0.0.0.0", None)  # noqa: S104


async def test_invalid_client_host_does_not_break_capture() -> None:
    h = _Harness()

    await h.run(_scope(client=("testclient", 50000)), [_body(b"")])

    assert str(h.event.ip) == "0.0.0.0"  # noqa: S104
    assert h.order == ["app", "sink"]


async def test_ipv6_client_is_captured() -> None:
    h = _Harness()

    await h.run(_scope(client=("2001:db8::7", 4000)), [_body(b"")])

    assert str(h.event.ip) == "2001:db8::7"


async def test_non_http_scopes_pass_through_untouched() -> None:
    h = _Harness()

    async def receive() -> Message:
        return {"type": "lifespan.startup"}

    async def send(message: Message) -> None:
        return None

    mw = CaptureMiddleware(h._app, h._sink)
    await mw({"type": "lifespan"}, receive, send)

    assert h.events == []
    assert h.order == ["app"]


async def test_forwarded_for_is_used_behind_a_trusted_proxy() -> None:
    h = _Harness(trusted=True)
    headers = [(b"x-forwarded-for", b"6.6.6.6"), (b"x-forwarded-for", b"203.0.113.5")]

    await h.run(_scope(client=("10.0.0.2", 40000), headers=headers), [_body(b"")])

    assert str(h.event.ip) == "203.0.113.5"
    assert h.event.port is None


async def test_forwarded_for_is_ignored_from_untrusted_peer() -> None:
    h = _Harness(trusted=True)
    headers = [(b"x-forwarded-for", b"6.6.6.6")]

    await h.run(_scope(client=("198.51.100.9", 40000), headers=headers), [_body(b"")])

    assert (str(h.event.ip), h.event.port) == ("198.51.100.9", 40000)


async def test_forwarded_for_is_ignored_when_no_proxy_is_trusted() -> None:
    h = _Harness()
    headers = [(b"x-forwarded-for", b"6.6.6.6")]

    await h.run(_scope(client=("10.0.0.2", 40000), headers=headers), [_body(b"")])

    assert str(h.event.ip) == "10.0.0.2"


async def test_identity_comes_from_ip_and_user_agent() -> None:
    h1, h2, h3 = _Harness(), _Harness(), _Harness()
    ua = [(b"user-agent", b"curl/8.5.0")]

    await h1.run(_scope(headers=ua), [_body(b"")])
    await h2.run(_scope(headers=ua, path="/other", raw_path=b"/other"), [_body(b"")])
    await h3.run(_scope(headers=[(b"user-agent", b"sqlmap/1.8")]), [_body(b"")])

    assert h1.event.world_id.startswith("w_")
    assert (h1.event.world_id, h1.event.session_id) == (h2.event.world_id, h2.event.session_id)
    assert h1.event.world_id != h3.event.world_id


async def test_identity_uses_the_real_client_behind_a_trusted_proxy() -> None:
    direct, proxied = _Harness(trusted=True), _Harness(trusted=True)
    ua = (b"user-agent", b"curl/8.5.0")

    await direct.run(_scope(client=("203.0.113.5", 1), headers=[ua]), [_body(b"")])
    await proxied.run(
        _scope(client=("10.0.0.2", 2), headers=[ua, (b"x-forwarded-for", b"203.0.113.5")]),
        [_body(b"")],
    )

    assert direct.event.world_id == proxied.event.world_id
