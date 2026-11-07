import asyncio
import json
from collections.abc import Awaitable, Callable
from typing import Any, cast

import httpx2
import pytest
from openai import AsyncOpenAI

from app.engine.llm_client import (
    LLMBadResponse,
    LLMClient,
    LLMTimeout,
    LLMUnavailable,
    Message,
)
from app.engine.llm_settings import TierConfig

Handler = Callable[[httpx2.Request], Awaitable[httpx2.Response] | httpx2.Response]


def _completion(
    content: str | None = "hello", finish: str = "stop", **extra: Any
) -> dict[str, Any]:
    return {
        "id": "c1",
        "object": "chat.completion",
        "created": 1,
        "model": "m",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": finish,
            }
        ],
        "usage": {"prompt_tokens": 11, "completion_tokens": 5, "total_tokens": 16},
        **extra,
    }


def _client(handler: Handler, *, timeout_s: float = 1.0, max_tokens: int = 256) -> LLMClient:
    config = TierConfig(
        base_url="http://llm.test/v1", model="m", timeout_s=timeout_s, max_tokens=max_tokens
    )
    http = httpx2.AsyncClient(transport=httpx2.MockTransport(cast(Any, handler)))
    sdk = AsyncOpenAI(
        base_url=config.base_url,
        api_key="unused",
        http_client=http,
        max_retries=0,
        timeout=timeout_s,
    )
    return LLMClient(config, client=sdk)


@pytest.fixture
def calls() -> list[httpx2.Request]:
    return []


async def test_returns_text_and_token_usage(calls: list[httpx2.Request]) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        calls.append(request)
        return httpx2.Response(200, json=_completion("hi there"))

    result = await _client(handler).complete([Message("user", "x")])

    assert result.text == "hi there"
    assert (result.prompt_tokens, result.completion_tokens, result.total_tokens) == (11, 5, 16)
    assert result.truncated is False


async def test_request_carries_model_messages_and_limits(calls: list[httpx2.Request]) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        calls.append(request)
        return httpx2.Response(200, json=_completion())

    await _client(handler, max_tokens=256).complete(
        [Message("system", "be a server"), Message("user", "GET /")], json_mode=True
    )

    (request,) = calls
    body = json.loads(request.content)
    assert request.url.path == "/v1/chat/completions"
    assert body["model"] == "m"
    assert body["messages"] == [
        {"role": "system", "content": "be a server"},
        {"role": "user", "content": "GET /"},
    ]
    assert body["max_tokens"] == 256
    assert body["temperature"] == 0.0
    assert body["response_format"] == {"type": "json_object"}
    assert body.get("stream") is not True


async def test_plain_calls_do_not_request_json_mode(calls: list[httpx2.Request]) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        calls.append(request)
        return httpx2.Response(200, json=_completion())

    await _client(handler).complete([Message("user", "x")])

    assert "response_format" not in json.loads(calls[0].content)


@pytest.mark.parametrize(("asked", "sent"), [(100, 100), (10_000, 256), (None, 256)])
async def test_max_tokens_can_only_be_lowered(
    calls: list[httpx2.Request], asked: int | None, sent: int
) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        calls.append(request)
        return httpx2.Response(200, json=_completion())

    await _client(handler, max_tokens=256).complete([Message("user", "x")], max_tokens=asked)

    assert json.loads(calls[0].content)["max_tokens"] == sent


async def test_truncated_output_is_flagged() -> None:
    result = await _client(
        lambda r: httpx2.Response(200, json=_completion('{"a":', finish="length"))
    ).complete([Message("user", "x")])

    assert result.truncated is True


async def test_slow_endpoint_times_out() -> None:
    async def handler(request: httpx2.Request) -> httpx2.Response:
        await asyncio.sleep(1)
        return httpx2.Response(200, json=_completion())

    with pytest.raises(LLMTimeout):
        await _client(handler, timeout_s=0.05).complete([Message("user", "x")])


async def test_server_errors_are_not_retried(calls: list[httpx2.Request]) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        calls.append(request)
        return httpx2.Response(500, json={"error": {"message": "boom"}})

    with pytest.raises(LLMUnavailable, match="500"):
        await _client(handler).complete([Message("user", "x")])
    assert len(calls) == 1


async def test_unreachable_endpoint() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("refused", request=request)

    with pytest.raises(LLMUnavailable, match="unreachable"):
        await _client(handler).complete([Message("user", "x")])


@pytest.mark.parametrize(
    "response",
    [
        httpx2.Response(200, json={**_completion(), "choices": []}),
        httpx2.Response(200, json=_completion(content=None)),
        httpx2.Response(200, json=_completion(content="")),
    ],
)
async def test_unusable_completions_are_bad_responses(response: httpx2.Response) -> None:
    with pytest.raises(LLMBadResponse):
        await _client(lambda r: response).complete([Message("user", "x")])


async def test_every_failure_is_an_llm_error() -> None:
    from app.engine.llm_client import LLMError

    assert issubclass(LLMTimeout, LLMError)
    assert issubclass(LLMUnavailable, LLMError)
    assert issubclass(LLMBadResponse, LLMError)


async def test_default_client_uses_the_tier_config() -> None:
    config = TierConfig(base_url="http://llm.test/v1", model="m", timeout_s=2.0, max_tokens=64)
    client = LLMClient(config)
    try:
        assert str(client._client.base_url).startswith("http://llm.test/v1")
        assert client._client.max_retries == 0
    finally:
        await client.aclose()
