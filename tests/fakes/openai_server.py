"""A fake OpenAI-compatible server for tests: real HTTP on a random local port.

It answers ``POST /v1/chat/completions`` and ``GET /v1/models`` with canned,
deterministic content, can be told to delay, fail or return garbage, and records every
request it received. Use it where a mocked transport is not enough: it exercises the
real HTTP stack (sockets, timeouts, connection errors), so the same fixture serves the
LLM client, the response engine and the fake-LLM persona tests.

    async def test_x(fake_llm: FakeOpenAIServer) -> None:
        fake_llm.enqueue(text='{"status_code": 200}')       # next answer
        fake_llm.enqueue(status=500)                         # the one after
        fake_llm.default = Scripted(delay_s=5)               # everything after that
        ... point a client at fake_llm.base_url ...
        assert fake_llm.requests[0].body["model"] == "m"
"""

import asyncio
import json
from collections import deque
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse


@dataclass(frozen=True)
class Scripted:
    """What the server does with one request."""

    text: str = "ok"
    status: int = 200
    delay_s: float = 0.0
    finish_reason: str = "stop"
    prompt_tokens: int = 10
    completion_tokens: int = 5
    # Sent verbatim (status 200) instead of a completion: malformed or odd bodies.
    raw: bytes | None = None


@dataclass(frozen=True)
class RecordedRequest:
    path: str
    body: dict[str, Any]
    headers: dict[str, str]


@dataclass
class FakeOpenAIServer:
    base_url: str = ""
    model: str = "fake-model"
    default: Scripted = field(default_factory=Scripted)
    # Called with the request body; its return value becomes the reply text. Wins over
    # ``Scripted.text`` for successful scripted answers.
    responder: Callable[[dict[str, Any]], str] | None = None
    requests: list[RecordedRequest] = field(default_factory=list)
    _queue: deque[Scripted] = field(default_factory=deque)

    def enqueue(self, **kwargs: Any) -> None:
        """Script the next answer; answers are used in order, then ``default``."""
        self._queue.append(Scripted(**kwargs))

    def _next(self) -> Scripted:
        return self._queue.popleft() if self._queue else self.default


def _completion(server: FakeOpenAIServer, step: Scripted, body: dict[str, Any]) -> dict[str, Any]:
    text = server.responder(body) if server.responder else step.text
    return {
        "id": "chatcmpl-fake",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": body.get("model", server.model),
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": text},
                "finish_reason": step.finish_reason,
            }
        ],
        "usage": {
            "prompt_tokens": step.prompt_tokens,
            "completion_tokens": step.completion_tokens,
            "total_tokens": step.prompt_tokens + step.completion_tokens,
        },
    }


def _build_app(server: FakeOpenAIServer) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.post("/v1/chat/completions")
    async def chat(request: Request) -> Response:
        try:
            body = json.loads(await request.body())
        except ValueError:
            body = {}
        server.requests.append(
            RecordedRequest(
                request.url.path, body, {k.lower(): v for k, v in request.headers.items()}
            )
        )
        step = server._next()
        if step.delay_s:
            await asyncio.sleep(step.delay_s)
        if step.raw is not None:
            return Response(step.raw, media_type="application/json")
        if step.status != 200:
            return JSONResponse(
                {"error": {"message": "scripted failure", "type": "server_error"}},
                status_code=step.status,
            )
        return JSONResponse(_completion(server, step, body))

    @app.get("/v1/models")
    async def models() -> dict[str, Any]:
        return {
            "object": "list",
            "data": [{"id": server.model, "object": "model", "created": 1, "owned_by": "fake"}],
        }

    return app


@asynccontextmanager
async def running_fake_openai_server() -> AsyncIterator[FakeOpenAIServer]:
    server = FakeOpenAIServer()
    config = uvicorn.Config(
        _build_app(server), host="127.0.0.1", port=0, log_level="warning", lifespan="off"
    )
    uvicorn_server = uvicorn.Server(config)
    task = asyncio.create_task(uvicorn_server.serve())
    try:
        async with asyncio.timeout(5):
            while not uvicorn_server.started:  # noqa: ASYNC110
                await asyncio.sleep(0.01)
        port = uvicorn_server.servers[0].sockets[0].getsockname()[1]
        server.base_url = f"http://127.0.0.1:{port}/v1"
        yield server
    finally:
        uvicorn_server.should_exit = True
        await task
