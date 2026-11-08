"""ResponseEngine with a real Redis cache and a real HTTP model endpoint."""

import pytest
from redis.asyncio import Redis

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
