"""The LLM client against a real HTTP server, to cover what a mocked transport cannot."""

import socket
import time

import pytest

from app.engine.llm_client import (
    LLMBadResponse,
    LLMClient,
    LLMTimeout,
    LLMUnavailable,
    Message,
)
from app.engine.llm_settings import TierConfig
from tests.fakes.openai_server import FakeOpenAIServer, Scripted


def _client(base_url: str, *, timeout_s: float = 2.0) -> LLMClient:
    return LLMClient(TierConfig(base_url=base_url, model="m", timeout_s=timeout_s, max_tokens=128))


async def test_round_trip(fake_llm: FakeOpenAIServer) -> None:
    fake_llm.enqueue(text='{"status_code": 200}', prompt_tokens=7, completion_tokens=3)
    client = _client(fake_llm.base_url)

    result = await client.complete([Message("system", "s"), Message("user", "GET /")])
    await client.aclose()

    assert result.text == '{"status_code": 200}'
    assert result.total_tokens == 10
    (request,) = fake_llm.requests
    assert request.path == "/v1/chat/completions"
    assert request.body["model"] == "m"
    assert request.body["messages"][1] == {"role": "user", "content": "GET /"}


async def test_responder_makes_replies_depend_on_the_request(fake_llm: FakeOpenAIServer) -> None:
    fake_llm.responder = lambda body: body["messages"][-1]["content"].upper()
    client = _client(fake_llm.base_url)

    result = await client.complete([Message("user", "abc")])
    await client.aclose()

    assert result.text == "ABC"


async def test_scripted_answers_are_used_in_order_then_the_default(
    fake_llm: FakeOpenAIServer,
) -> None:
    fake_llm.enqueue(text="first")
    fake_llm.enqueue(text="second")
    fake_llm.default = Scripted(text="after")
    client = _client(fake_llm.base_url)

    texts = [(await client.complete([Message("user", "x")])).text for _ in range(4)]
    await client.aclose()

    assert texts == ["first", "second", "after", "after"]


async def test_slow_answer_times_out_close_to_the_deadline(fake_llm: FakeOpenAIServer) -> None:
    fake_llm.default = Scripted(delay_s=5)
    client = _client(fake_llm.base_url, timeout_s=0.2)

    started = time.monotonic()
    with pytest.raises(LLMTimeout):
        await client.complete([Message("user", "x")])
    elapsed = time.monotonic() - started
    await client.aclose()

    assert elapsed < 1.0


async def test_server_error_is_unavailable_and_not_retried(fake_llm: FakeOpenAIServer) -> None:
    fake_llm.default = Scripted(status=503)
    client = _client(fake_llm.base_url)

    with pytest.raises(LLMUnavailable, match="503"):
        await client.complete([Message("user", "x")])
    await client.aclose()

    assert len(fake_llm.requests) == 1


async def test_garbage_body_is_a_bad_response(fake_llm: FakeOpenAIServer) -> None:
    fake_llm.default = Scripted(raw=b"<html>not json</html>")
    client = _client(fake_llm.base_url)

    with pytest.raises(LLMBadResponse):
        await client.complete([Message("user", "x")])
    await client.aclose()


async def test_length_finish_reason_marks_the_answer_truncated(
    fake_llm: FakeOpenAIServer,
) -> None:
    fake_llm.default = Scripted(text='{"a":', finish_reason="length")
    client = _client(fake_llm.base_url)

    result = await client.complete([Message("user", "x")])
    await client.aclose()

    assert result.truncated is True


async def test_nothing_listening_is_unavailable() -> None:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    client = _client(f"http://127.0.0.1:{port}/v1")  # the port is free again: refused

    with pytest.raises(LLMUnavailable):
        await client.complete([Message("user", "x")])
    await client.aclose()


async def test_models_endpoint(fake_llm: FakeOpenAIServer) -> None:
    import httpx

    async with httpx.AsyncClient() as http:
        response = await http.get(f"{fake_llm.base_url}/models")

    assert [m["id"] for m in response.json()["data"]] == ["fake-model"]
