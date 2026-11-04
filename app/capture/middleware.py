import hashlib
import time
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address, ip_address

from app.asgi_types import ASGIApp, Message, Receive, Scope, Send
from app.capture.client_ip import IPNetwork, resolve_client_ip
from app.capture.fingerprint import fingerprint_v1
from app.metrics import observe_request
from app.personas.base import DEFAULT_PERSONA, PERSONA_SCOPE_KEY, PersonaConfig
from domain.captured_request import CapturedRequest

MAX_BODY_EXCERPT_BYTES = 1024 * 1024
MAX_BODY_READ_BYTES = 32 * 1024 * 1024

# The response engine reports how a request was answered through the ASGI scope.
TIER_SCOPE_KEY = "mirage.tier"
TOKENS_SCOPE_KEY = "mirage.tokens_used"

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
    """Records every HTTP request as one CapturedRequest event.

    The body is read here (the catch-all never reads it), hashed in full and kept
    up to a limit, then replayed to the downstream app. The event is published once
    the response is done, completed with status, latency, tier and persona. It is
    published from ``finally`` so requests that crash the app are still recorded.
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
        captured = _build(scope, body, self.trusted_proxies)

        # Latency is measured from here, so slow clients uploading a body do not inflate it.
        started = time.perf_counter()
        status: int | None = None

        async def send_and_note_status(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        try:
            await self.app(scope, _replay(body, receive), send_and_note_status)
        except Exception:
            if status is None:
                status = 500
            raise
        finally:
            duration_s = time.perf_counter() - started
            persona = scope.get(PERSONA_SCOPE_KEY)
            tier = scope.get(TIER_SCOPE_KEY, 0)
            observe_request(
                persona=persona.name
                if isinstance(persona, PersonaConfig)
                else DEFAULT_PERSONA.name,
                tier=tier,
                status=status,
                duration_s=duration_s,
            )
            completed = captured.model_copy(
                update={"persona": persona.name if isinstance(persona, PersonaConfig) else None}
            ).with_response(
                tier=tier,
                status=status,
                latency_ms=round(duration_s * 1000),
                tokens_used=scope.get(TOKENS_SCOPE_KEY, 0),
            )
            await self.sink(completed)
