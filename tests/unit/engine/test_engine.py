from datetime import UTC, datetime
from ipaddress import ip_address
from uuid import uuid4

import pytest

from app.engine.engine import ResponseEngine, Source
from app.engine.llm_client import Completion, LLMTimeout, LLMUnavailable, Message
from app.engine.response import GeneratedResponse
from app.engine.signature import request_signature
from domain.captured_request import CapturedRequest

PROMPT = "You are a test service."
FALLBACK = GeneratedResponse(status_code=404, body="nope")
MODEL_JSON = '{"status_code": 200, "headers": {"content-type": "application/json"}, "body": "{}"}'


def _req(path: str = "/api/v1/orders") -> CapturedRequest:
    return CapturedRequest(
        ts=datetime.now(UTC),
        session_id=uuid4(),
        world_id="w",
        ip=ip_address("203.0.113.9"),
        method="GET",
        path=path,
    )


class MemoryCache:
    def __init__(self) -> None:
        self.items: dict[str, GeneratedResponse] = {}

    async def get(self, signature: str) -> GeneratedResponse | None:
        return self.items.get(signature)

    async def set(self, signature: str, response: GeneratedResponse) -> bool:
        self.items[signature] = response
        return True


class StubModel:
    def __init__(self, *outcomes: str | Exception) -> None:
        self.outcomes = list(outcomes)
        self.calls: list[list[Message]] = []

    async def complete(
        self,
        messages: list[Message],
        *,
        max_tokens: int | None = None,
        temperature: float = 0.0,
        json_mode: bool = False,
    ) -> Completion:
        self.calls.append(messages)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return Completion(text=outcome, prompt_tokens=1, completion_tokens=1, truncated=False)


async def _respond(engine: ResponseEngine, req: CapturedRequest) -> tuple[Source, int, str]:
    result = await engine.respond(req, persona_prompt=PROMPT, fallback=lambda: FALLBACK)
    return result.source, result.response.status_code, result.response.body


async def test_miss_asks_the_model_and_caches_the_answer() -> None:
    cache, model = MemoryCache(), StubModel(MODEL_JSON)
    engine = ResponseEngine(cache=cache, model=model)
    req = _req()

    assert await _respond(engine, req) == (Source.MODEL, 200, "{}")
    assert request_signature(req) in cache.items


async def test_hit_is_served_without_calling_the_model() -> None:
    cache, model = MemoryCache(), StubModel(MODEL_JSON)
    engine = ResponseEngine(cache=cache, model=model)

    await _respond(engine, _req())
    source, _, _ = await _respond(engine, _req())

    assert source is Source.CACHE
    assert len(model.calls) == 1


@pytest.mark.parametrize(
    "outcome",
    [
        LLMTimeout("slow"),
        LLMUnavailable("down"),
        "not json at all",
        '{"status_code": 99, "body": ""}',
        '{"status_code": 200, "headers": {"x": "a\\r\\nSet-Cookie: b=1"}}',
    ],
)
async def test_model_failure_falls_back_and_is_not_cached(outcome: str | Exception) -> None:
    cache, model = MemoryCache(), StubModel(outcome, MODEL_JSON)
    engine = ResponseEngine(cache=cache, model=model)

    assert await _respond(engine, _req()) == (Source.FALLBACK, 404, "nope")
    assert cache.items == {}
    # The next request tries the model again.
    assert (await _respond(engine, _req()))[0] is Source.MODEL


async def test_tier_property() -> None:
    engine = ResponseEngine(cache=MemoryCache(), model=StubModel(MODEL_JSON))

    first = await engine.respond(_req(), persona_prompt=PROMPT, fallback=lambda: FALLBACK)
    second = await engine.respond(_req(), persona_prompt=PROMPT, fallback=lambda: FALLBACK)

    assert (first.tier, second.tier) == (1, 0)


async def test_prompt_carries_the_persona_and_the_request() -> None:
    model = StubModel(MODEL_JSON)
    engine = ResponseEngine(cache=MemoryCache(), model=model)

    await _respond(engine, _req("/api/v1/orders/7"))

    system, user = model.calls[0]
    assert PROMPT in system.content
    assert "/api/v1/orders/7" in user.content
