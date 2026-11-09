"""A POST that creates an object and a later GET must agree, end to end.

The engine, a real Redis (cache, delta, budget-free) and a fake model that behaves like
a small service: it reads the world state out of the prompt and answers from it. If the
engine ever failed to give the model the world, or served a stale cached answer, the
last GET would come back 404.
"""

import json
import re
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any
from uuid import uuid4

import pytest
from redis.asyncio import Redis

from app.engine.cache import ResponseCache
from app.engine.engine import ResponseEngine, Source
from app.engine.llm_client import LLMClient
from app.engine.llm_settings import TierConfig
from app.engine.world import WorldState
from app.engine.world_delta import DeltaStore
from domain.captured_request import CapturedRequest
from tests.fakes.openai_server import FakeOpenAIServer
from tests.unit.engine.test_engine import FALLBACK, PROMPT

pytestmark = pytest.mark.integration

_BLOCK = re.compile(r"BEGIN (WORLD STATE|CLIENT REQUEST) (\w+)\n(.*)\nEND \1 \2", re.DOTALL)


def _blocks(body: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    user = body["messages"][1]["content"]
    found = {m.group(1): json.loads(m.group(3)) for m in _BLOCK.finditer(user)}
    return found["WORLD STATE"], found["CLIENT REQUEST"]


def _service(body: dict[str, Any]) -> str:
    """A tiny users API that trusts only the world state in the prompt."""
    world, request = _blocks(body)
    users = world.get("users", {})
    if request["method"] == "POST":
        user_id = users["next_id"]
        payload = json.loads(request["body"])
        return json.dumps(
            {
                "status_code": 201,
                "headers": {"content-type": "application/json"},
                "body": json.dumps({"data": {"id": user_id, **payload}}),
                "state_updates": [
                    {"op": "create", "kind": "users", "id": user_id, "fields": payload}
                ],
            }
        )
    if request["method"] == "DELETE":
        user_id = int(request["path"].rsplit("/", 1)[1])
        return json.dumps(
            {
                "status_code": 204,
                "state_updates": [{"op": "delete", "kind": "users", "id": user_id}],
            }
        )
    (user,) = users["requested"].values()
    if user is None:
        return json.dumps({"status_code": 404, "body": '{"error":"Not Found"}'})
    return json.dumps({"status_code": 200, "body": json.dumps({"data": user})})


def _req(method: str, path: str, body: str = "") -> CapturedRequest:
    return CapturedRequest(
        ts=datetime.now(UTC),
        session_id=uuid4(),
        world_id="w_consistency",
        ip=ip_address("203.0.113.9"),
        method=method,
        path=path,
        body_excerpt=body,
    )


@pytest.fixture
async def engine(redis: Redis, fake_llm: FakeOpenAIServer) -> ResponseEngine:
    await redis.flushdb()
    fake_llm.responder = _service
    config = TierConfig(base_url=fake_llm.base_url, model="m", timeout_s=2.0, max_tokens=256)
    return ResponseEngine(
        cache=ResponseCache(redis),
        model=LLMClient(config),
        world=WorldState(DeltaStore(redis)),
    )


async def _call(engine: ResponseEngine, method: str, path: str, body: str = "") -> Any:
    return await engine.respond(
        _req(method, path, body), persona_prompt=PROMPT, fallback=lambda: FALLBACK
    )


async def test_created_object_is_found_by_a_later_get(engine: ResponseEngine) -> None:
    missing = await _call(engine, "GET", "/api/v1/users/1001")
    created = await _call(engine, "POST", "/api/v1/users", '{"email": "eve@example.com"}')
    found = await _call(engine, "GET", "/api/v1/users/1001")

    assert missing.response.status_code == 404
    assert created.response.status_code == 201
    assert json.loads(created.response.body)["data"]["id"] == 1001
    assert found.source is Source.MODEL  # not the stale "not found" from the first GET
    assert found.response.status_code == 200
    assert json.loads(found.response.body)["data"]["email"] == "eve@example.com"


async def test_second_create_gets_a_new_id(engine: ResponseEngine) -> None:
    first = await _call(engine, "POST", "/api/v1/users", '{"email": "a@example.com"}')
    second = await _call(engine, "POST", "/api/v1/users", '{"email": "b@example.com"}')

    ids = [json.loads(r.response.body)["data"]["id"] for r in (first, second)]
    assert ids == [1001, 1002]


async def test_deleted_object_stays_gone(engine: ResponseEngine) -> None:
    before = await _call(engine, "GET", "/api/v1/users/5")
    await _call(engine, "DELETE", "/api/v1/users/5")
    after = await _call(engine, "GET", "/api/v1/users/5")

    assert before.response.status_code == 200
    assert after.response.status_code == 404


async def test_another_attackers_world_is_unaffected(engine: ResponseEngine, redis: Redis) -> None:
    await _call(engine, "POST", "/api/v1/users", '{"email": "eve@example.com"}')
    other = CapturedRequest(
        ts=datetime.now(UTC),
        session_id=uuid4(),
        world_id="w_someone_else",
        ip=ip_address("198.51.100.4"),
        method="GET",
        path="/api/v1/users/1001",
    )

    result = await engine.respond(other, persona_prompt=PROMPT, fallback=lambda: FALLBACK)

    assert result.response.status_code == 404
