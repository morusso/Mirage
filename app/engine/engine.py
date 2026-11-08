"""ResponseEngine: decides who answers a request.

Order of tiers:

0. The response cache, keyed by request signature. Free and instant.
1. The local model, on a cache miss. Its answer is validated and cached.
2. If the model fails (timeout, unreachable, unusable output), the static fallback
   response the caller supplied, which is what the honeypot answered before it had a
   model. A failure is never cached, so the next request tries the model again.

``respond`` never raises for model or cache problems: an attacker must not be able to
turn a flaky model into an error page that gives the honeypot away.
"""

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

import structlog
from pydantic import ValidationError

from app.engine.llm_client import Completion, LLMError, Message
from app.engine.prompts.builder import build_messages
from app.engine.response import GeneratedResponse
from app.engine.signature import request_signature
from domain.captured_request import CapturedRequest

logger = structlog.get_logger()

# Tokens the model may spend on one answer: a JSON envelope plus a small body.
RESPONSE_MAX_TOKENS = 512


class Source(StrEnum):
    CACHE = "cache"  # tier 0 hit
    MODEL = "model"  # tier 1, freshly generated
    FALLBACK = "fallback"  # tier 1 failed, static answer


@dataclass(frozen=True, slots=True)
class EngineResult:
    response: GeneratedResponse
    source: Source

    @property
    def tier(self) -> int:
        return 1 if self.source is Source.MODEL else 0


class CacheLike(Protocol):
    async def get(self, signature: str) -> GeneratedResponse | None: ...
    async def set(self, signature: str, response: GeneratedResponse) -> bool: ...


class ModelLike(Protocol):
    async def complete(
        self,
        messages: list[Message],
        *,
        max_tokens: int | None = None,
        temperature: float = 0.0,
        json_mode: bool = False,
    ) -> Completion: ...


class ResponseEngine:
    def __init__(self, *, cache: CacheLike, model: ModelLike) -> None:
        self.cache = cache
        self.model = model

    async def respond(
        self,
        request: CapturedRequest,
        *,
        persona_prompt: str,
        fallback: Callable[[], GeneratedResponse],
    ) -> EngineResult:
        signature = request_signature(request)

        cached = await self.cache.get(signature)
        if cached is not None:
            return EngineResult(cached, Source.CACHE)

        generated = await self._generate(request, persona_prompt)
        if generated is None:
            return EngineResult(fallback(), Source.FALLBACK)

        await self.cache.set(signature, generated)
        return EngineResult(generated, Source.MODEL)

    async def _generate(
        self, request: CapturedRequest, persona_prompt: str
    ) -> GeneratedResponse | None:
        messages = build_messages(persona_prompt=persona_prompt, request=request)
        try:
            completion = await self.model.complete(
                messages, max_tokens=RESPONSE_MAX_TOKENS, json_mode=True
            )
        except LLMError as exc:
            logger.warning("tier1_failed", error=type(exc).__name__)
            return None
        try:
            return GeneratedResponse.model_validate_json(completion.text)
        except ValidationError:
            # Details are not logged: they quote attacker-influenced model output.
            logger.warning("tier1_output_invalid", truncated=completion.truncated)
            return None
