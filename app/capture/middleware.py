import hashlib
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address, ip_address

from app.asgi_types import ASGIApp, Message, Receive, Scope, Send
from app.capture.client_ip import IPNetwork, resolve_client_ip
from app.capture.fingerprint import fingerprint_v1
from domain.captured_request import CapturedRequest

MAX_BODY_EXCERPT_BYTES = 1024 * 1024
MAX_BODY_READ_BYTES = 32 * 1024 * 1024

Sink = Callable[[CapturedRequest], Awaitable[None]]


@dataclass(frozen=True)
class _Body:
    kept: bytes
    size: int
    sha256: str | None
    stopped_early: bool
    disconnected: bool

    @property
    def truncated(self) -> bool:
        return self.size > len(self.kept) or self.stopped_early


def _text(data: bytes) -> str:
    # Attackers send arbitrary bytes; keep them visible instead of failing.
    return data.decode("utf-8", errors="backslashreplace")


async def _read_body(receive: Receive, max_kept: int, max_read: int) -> _Body:
    digest = hashlib.sha256()
    kept = bytearray()
    size = 0
    stopped_early = False
    disconnected = False

    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            disconnected = True
            break
        chunk: bytes = message.get("body", b"")
        size += len(chunk)
        digest.update(chunk)
        room = max_kept - len(kept)
        if room > 0:
            kept += chunk[:room]
        if not message.get("more_body", False):
            break
        if size >= max_read:
            stopped_early = True
            break

    return _Body(
        kept=bytes(kept),
        size=size,
        sha256=digest.hexdigest() if size else None,
        stopped_early=stopped_early,
        disconnected=disconnected,
    )


def _replay(body: _Body, receive: Receive) -> Receive:
    """Receive callable that hands the already-read body to the downstream app."""
    delivered = False

    async def replayed() -> Message:
        nonlocal delivered
        if not delivered:
            delivered = True
            if body.disconnected:
                return {"type": "http.disconnect"}
            return {"type": "http.request", "body": body.kept, "more_body": False}
        if body.stopped_early:
            return {"type": "http.disconnect"}
        return await receive()

    return replayed


_UNKNOWN_IP = IPv4Address("0.0.0.0")  # noqa: S104 - "unknown" marker, not a bind


def _client(
    scope: Scope, trusted_proxies: tuple[IPNetwork, ...]
) -> tuple[IPv4Address | IPv6Address, int | None]:
    """Client address and port; never raises (capture must not break requests).

    Behind a trusted proxy the real client comes from X-Forwarded-For and its
    source port is unknown.
    """
    client = scope.get("client")
    if not client:
        return _UNKNOWN_IP, None
    try:
        peer = ip_address(client[0])
    except ValueError:
        return _UNKNOWN_IP, None

    forwarded = ",".join(
        _text(v) for k, v in scope.get("headers", []) if k.lower() == b"x-forwarded-for"
    )
    ip = resolve_client_ip(peer, forwarded or None, trusted_proxies)
    return ip, client[1] if ip == peer else None


def _user_agent(scope: Scope) -> str | None:
    for key, value in scope.get("headers", []):
        if key.lower() == b"user-agent":
            return _text(value)
    return None


def _build(scope: Scope, body: _Body, trusted_proxies: tuple[IPNetwork, ...]) -> CapturedRequest:
    ip, port = _client(scope, trusted_proxies)
    fingerprint = fingerprint_v1(ip, _user_agent(scope))
    raw_path: bytes = scope.get("raw_path") or scope["path"].encode()
    return CapturedRequest(
        ts=datetime.now(UTC),
        session_id=fingerprint.session_id,
        world_id=fingerprint.world_id,
        ip=ip,
        port=port,
        method=scope["method"],
        path=_text(raw_path),
        query=_text(scope.get("query_string", b"")),
        headers=[(_text(k), _text(v)) for k, v in scope.get("headers", [])],
        body_excerpt=_text(body.kept),
        body_size=body.size,
        body_sha256=body.sha256,
        body_truncated=body.truncated,
    )


class CaptureMiddleware:
    """Records every HTTP request as a CapturedRequest before the app sees it.

    The body is read here (the catch-all never reads it), hashed in full and kept
    up to a limit, then replayed to the downstream app.
    """

    def __init__(
        self,
        app: ASGIApp,
        sink: Sink,
        *,
        max_body_excerpt: int = MAX_BODY_EXCERPT_BYTES,
        max_body_read: int = MAX_BODY_READ_BYTES,
        trusted_proxies: Iterable[IPNetwork] = (),
    ) -> None:
        self.app = app
        self.sink = sink
        self.trusted_proxies = tuple(trusted_proxies)
        self.max_body_excerpt = max_body_excerpt
        self.max_body_read = max_body_read

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        body = await _read_body(receive, self.max_body_excerpt, self.max_body_read)
        await self.sink(_build(scope, body, self.trusted_proxies))
        await self.app(scope, _replay(body, receive), send)
