"""ResponseEngine with a real Redis cache and a real HTTP model endpoint."""

import pytest
from redis.asyncio import Redis

from app.engine.budget import BudgetManager, TierBudget
from app.engine.cache import ResponseCache
from app.engine.engine import ResponseEngine, Source
from app.engine.llm_client import LLMClient
from app.engine.llm_settings import TierConfig
from app.engine.response import GeneratedResponse
from tests.fakes.openai_server import FakeOpenAIServer
from tests.unit.engine.test_engine import FALLBACK, MODEL_JSON, PROMPT, _req

pytestmark = pytest.mark.integration


async def _engine(redis: Redis, base_url: str) -> ResponseEngine:
    await redis.flushdb()  # the redis fixture is shared; signatures repeat across tests
    config = TierConfig(base_url=base_url, model="m", timeout_s=1.0, max_tokens=256)
    return ResponseEngine(cache=ResponseCache(redis), model=LLMClient(config))


async def test_second_identical_request_is_served_from_redis(
    redis: Redis, fake_llm: FakeOpenAIServer
) -> None:
    fake_llm.enqueue(text=MODEL_JSON)
    engine = await _engine(redis, fake_llm.base_url)

    first = await engine.respond(_req(), persona_prompt=PROMPT, fallback=lambda: FALLBACK)
    second = await engine.respond(_req(), persona_prompt=PROMPT, fallback=lambda: FALLBACK)

    assert (first.source, second.source) == (Source.MODEL, Source.CACHE)
    assert second.response == first.response
    assert len(fake_llm.requests) == 1


async def test_model_outage_answers_with_the_fallback(
    redis: Redis, fake_llm: FakeOpenAIServer
) -> None:
    fake_llm.enqueue(status=503)
    engine = await _engine(redis, fake_llm.base_url)

    result = await engine.respond(_req(), persona_prompt=PROMPT, fallback=lambda: FALLBACK)

    assert result.source is Source.FALLBACK
    assert isinstance(result.response, GeneratedResponse)
    assert result.response == FALLBACK


async def test_scanner_is_stopped_by_the_budget_without_an_error_response(
    redis: Redis, fake_llm: FakeOpenAIServer
) -> None:
    await redis.flushdb()
    config = TierConfig(base_url=fake_llm.base_url, model="m", timeout_s=1.0, max_tokens=256)
    # Each answer really costs 400 tokens but is charged ~700 up front, so a 1500-token IP
    # budget runs out after a few answers. The clock is frozen: no window rollover.
    budget = BudgetManager(
        redis, limits={1: TierBudget(ip=1500, subnet=0, total=0)}, clock=lambda: 60_000.0
    )
    engine = ResponseEngine(cache=ResponseCache(redis), model=LLMClient(config), budget=budget)
    for _ in range(10):
        fake_llm.enqueue(text=MODEL_JSON, prompt_tokens=300, completion_tokens=100)

    results = [
        await engine.respond(
            _req(f"/api/v1/o{i}"), persona_prompt=PROMPT, fallback=lambda: FALLBACK
        )
        for i in range(10)
    ]

    sources = [r.source for r in results]
    first_refused = sources.index(Source.OVER_BUDGET)
    assert 2 <= first_refused < 10
    assert set(sources[:first_refused]) == {Source.MODEL}
    assert set(sources[first_refused:]) == {Source.OVER_BUDGET}  # and it stays that way
    assert all(r.response.status_code != 429 for r in results)
    assert len(fake_llm.requests) == first_refused
