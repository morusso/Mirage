from collections.abc import AsyncIterator, Awaitable, Callable, MutableMapping
from typing import Any

import httpx
import pytest
from httpx import ASGITransport

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]


async def _placeholder_app(scope: Scope, receive: Receive, send: Send) -> None:
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    transport = ASGITransport(app=_placeholder_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
