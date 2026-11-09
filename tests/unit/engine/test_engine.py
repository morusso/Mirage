import json
from datetime import UTC, datetime
from ipaddress import ip_address
from uuid import uuid4

import pytest
from prometheus_client import REGISTRY

from app.engine.engine import ResponseEngine, Source
from app.engine.llm_client import (
    Completion,
    LLMBadResponse,
    LLMTimeout,
    LLMUnavailable,
    Message,
)
from app.engine.response import GeneratedResponse
from app.engine.signature import request_signature
from app.engine.world import ApplyResult
from app.engine.world_delta import WorldStateUnavailable
from app.engine.world_updates import StateUpdate
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


def _failures(reason: str) -> float:
    return REGISTRY.get_sample_value("mirage_llm_failures_total", {"reason": reason}) or 0.0


def _fallbacks() -> float:
    return REGISTRY.get_sample_value("mirage_fallbacks_total") or 0.0


@pytest.mark.parametrize(
    ("outcome", "reason"),
    [
        (LLMTimeout("slow"), "timeout"),
        (LLMUnavailable("down"), "unavailable"),
        (LLMBadResponse("junk"), "bad_response"),
        ("not json at all", "invalid_output"),
    ],
)
async def test_failures_are_counted_by_reason_with_a_fallback(
    outcome: str | Exception, reason: str
) -> None:
    failures, fallbacks = _failures(reason), _fallbacks()
    engine = ResponseEngine(cache=MemoryCache(), model=StubModel(outcome))

    await _respond(engine, _req())

    assert _failures(reason) == failures + 1
    assert _fallbacks() == fallbacks + 1


async def test_success_and_cache_hit_count_no_failure() -> None:
    before = (_failures("timeout"), _fallbacks())
    engine = ResponseEngine(cache=MemoryCache(), model=StubModel(MODEL_JSON))

    await _respond(engine, _req())
    await _respond(engine, _req())

    assert (_failures("timeout"), _fallbacks()) == before


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


class StubBudget:
    def __init__(self, *, allow: bool = True) -> None:
        self.permit = allow
        self.charged: list[int] = []
        self.settled: list[tuple[int, int]] = []

    async def allow(self, request: CapturedRequest, tier: int, est_tokens: int = 300) -> bool:
        self.charged.append(est_tokens)
        return self.permit

    async def settle(
        self, request: CapturedRequest, tier: int, *, estimated: int, actual: int
    ) -> None:
        self.settled.append((estimated, actual))


async def test_over_budget_skips_the_model_and_serves_the_fallback() -> None:
    model, budget = StubModel(MODEL_JSON), StubBudget(allow=False)
    cache = MemoryCache()
    engine = ResponseEngine(cache=cache, model=model, budget=budget)

    result = await engine.respond(_req(), persona_prompt=PROMPT, fallback=lambda: FALLBACK)

    assert (result.source, result.tier, result.response) == (Source.OVER_BUDGET, 0, FALLBACK)
    assert model.calls == []
    assert cache.items == {}
    assert budget.settled == []


async def test_over_budget_is_not_counted_as_a_model_failure() -> None:
    failures, fallbacks = _failures("timeout"), _fallbacks()
    engine = ResponseEngine(cache=MemoryCache(), model=StubModel(), budget=StubBudget(allow=False))

    await _respond(engine, _req())

    assert (_failures("timeout"), _fallbacks()) == (failures, fallbacks)


async def test_cache_hit_costs_no_budget() -> None:
    cache, budget = MemoryCache(), StubBudget()
    engine = ResponseEngine(cache=cache, model=StubModel(MODEL_JSON), budget=budget)
    await _respond(engine, _req())
    budget.charged.clear()

    assert (await _respond(engine, _req()))[0] is Source.CACHE
    assert budget.charged == []


async def test_estimate_is_corrected_to_real_usage_after_the_call() -> None:
    budget = StubBudget()
    engine = ResponseEngine(cache=MemoryCache(), model=StubModel(MODEL_JSON), budget=budget)

    result = await engine.respond(_req(), persona_prompt=PROMPT, fallback=lambda: FALLBACK)

    (estimated,) = budget.charged
    assert estimated > 512  # worst case: prompt plus the whole completion allowance
    assert budget.settled == [(estimated, 2)]  # the stub model reports 1 + 1 tokens
    assert result.tokens_used == 2


@pytest.mark.parametrize(
    ("outcome", "refunded"),
    [(LLMUnavailable("down"), True), (LLMTimeout("slow"), False)],
)
async def test_failed_call_is_refunded_only_if_the_model_was_never_reached(
    outcome: Exception, refunded: bool
) -> None:
    budget = StubBudget()
    engine = ResponseEngine(cache=MemoryCache(), model=StubModel(outcome), budget=budget)

    await _respond(engine, _req())

    (estimated,) = budget.charged
    assert budget.settled == ([(estimated, 0)] if refunded else [])


async def test_rejected_model_output_still_settles_the_tokens_it_used() -> None:
    budget = StubBudget()
    engine = ResponseEngine(cache=MemoryCache(), model=StubModel("not json"), budget=budget)

    result = await engine.respond(_req(), persona_prompt=PROMPT, fallback=lambda: FALLBACK)

    assert result.source is Source.FALLBACK
    assert budget.settled[0][1] == 2


class StubWorld:
    def __init__(self, snapshot: dict[str, object] | None = None, *, down: bool = False) -> None:
        self.snapshot = snapshot or {}
        self.down = down
        self.applied: list[list[StateUpdate]] = []

    async def snapshot_for(self, world_id: str, request: CapturedRequest) -> dict[str, object]:
        if self.down:
            raise WorldStateUnavailable("ConnectionError")
        return self.snapshot

    async def apply(self, world_id: str, updates: list[StateUpdate]) -> ApplyResult:
        if self.down:
            raise WorldStateUnavailable("ConnectionError")
        self.applied.append(updates)
        return ApplyResult(len(updates))


CREATE = {"op": "create", "kind": "users", "id": 1001, "fields": {"email": "a@example.com"}}


def _model_json(**extra: object) -> str:
    return json.dumps({"status_code": 201, "headers": {}, "body": "{}", **extra})


async def test_snapshot_reaches_the_prompt() -> None:
    model = StubModel(MODEL_JSON)
    world = StubWorld({"users": {"requested": {"7": None}}})
    engine = ResponseEngine(cache=MemoryCache(), model=model, world=world)

    await _respond(engine, _req())

    assert '"requested":{"7":null}' in model.calls[0][1].content


async def test_world_independent_answer_is_cached() -> None:
    cache = MemoryCache()
    engine = ResponseEngine(cache=cache, model=StubModel(MODEL_JSON), world=StubWorld())

    await _respond(engine, _req())

    assert len(cache.items) == 1


async def test_answer_that_used_the_world_is_not_cached() -> None:
    cache = MemoryCache()
    world = StubWorld({"users": {"requested": {"7": None}}})
    engine = ResponseEngine(cache=cache, model=StubModel(MODEL_JSON), world=world)

    await _respond(engine, _req())

    assert cache.items == {}


async def test_state_updates_are_validated_applied_and_stop_caching() -> None:
    cache, world = MemoryCache(), StubWorld()
    reply = _model_json(state_updates=[CREATE, {"op": "explode"}, "junk"])
    engine = ResponseEngine(cache=cache, model=StubModel(reply), world=world)

    result = await engine.respond(_req(), persona_prompt=PROMPT, fallback=lambda: FALLBACK)

    assert result.source is Source.MODEL
    assert [[u.op for u in batch] for batch in world.applied] == [["create"]]
    assert cache.items == {}


async def test_updates_are_never_applied_without_a_world() -> None:
    cache = MemoryCache()
    engine = ResponseEngine(cache=cache, model=StubModel(_model_json(state_updates=[CREATE])))

    await _respond(engine, _req())

    assert len(cache.items) == 1  # nothing to apply them to, so it behaves as before


async def test_state_updates_do_not_leak_into_the_cache() -> None:
    cache = MemoryCache()
    engine = ResponseEngine(
        cache=cache, model=StubModel(_model_json(state_updates=[])), world=StubWorld()
    )

    await _respond(engine, _req())

    (cached,) = cache.items.values()
    assert "state_updates" not in cached.model_dump_json()


async def test_garbage_state_updates_are_ignored() -> None:
    world = StubWorld()
    engine = ResponseEngine(
        cache=MemoryCache(), model=StubModel(_model_json(state_updates="drop all")), world=world
    )

    assert (await _respond(engine, _req()))[0] is Source.MODEL
    assert world.applied == []


async def test_world_down_before_the_call_falls_back_without_asking_the_model() -> None:
    fallbacks = _fallbacks()
    model = StubModel(MODEL_JSON)
    engine = ResponseEngine(cache=MemoryCache(), model=model, world=StubWorld(down=True))

    assert await _respond(engine, _req()) == (Source.FALLBACK, 404, "nope")
    assert model.calls == []
    assert _fallbacks() == fallbacks + 1


async def test_world_down_after_the_call_still_serves_the_answer() -> None:
    class FlakyWorld(StubWorld):
        async def snapshot_for(self, world_id: str, request: CapturedRequest) -> dict[str, object]:
            return {}

    cache = MemoryCache()
    world = FlakyWorld(down=True)
    engine = ResponseEngine(
        cache=cache, model=StubModel(_model_json(state_updates=[CREATE])), world=world
    )

    result = await engine.respond(_req(), persona_prompt=PROMPT, fallback=lambda: FALLBACK)

    assert (result.source, result.response.status_code) == (Source.MODEL, 201)
    assert cache.items == {}
