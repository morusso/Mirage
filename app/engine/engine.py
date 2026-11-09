"""ResponseEngine: decides who answers a request.

Order of tiers:

0. The response cache, keyed by request signature. Free and instant.
1. The local model, on a cache miss, if the request's token budget has room. Its answer
   is validated and cached.
2. If the model fails (timeout, unreachable, unusable output) or the budget has no
   room, the static fallback response the caller supplied, which is what the honeypot
   answered before it had a model. Neither is cached, so the next request tries again.
   Going over budget is never an error page or a 429: the attacker just gets tier 0.

``respond`` never raises for model or cache problems: an attacker must not be able to
turn a flaky model into an error page that gives the honeypot away.
"""

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

import structlog
from pydantic import ValidationError

from app.engine.budget import estimate_tokens
from app.engine.llm_client import (
    Completion,
    LLMBadResponse,
    LLMError,
    LLMTimeout,
    LLMUnavailable,
    Message,
)
from app.engine.prompts.builder import build_messages
from app.engine.response import GeneratedResponse
from app.engine.signature import request_signature
from app.metrics import observe_llm_failure
from domain.captured_request import CapturedRequest

logger = structlog.get_logger()

# Tokens the model may spend on one answer: a JSON envelope plus a small body.
RESPONSE_MAX_TOKENS = 512
# The budget tier this engine charges; the strong tier gets its own engine later.
TIER1 = 1


class Source(StrEnum):
    CACHE = "cache"  # tier 0 hit
    MODEL = "model"  # tier 1, freshly generated
    FALLBACK = "fallback"  # tier 1 failed, static answer
    OVER_BUDGET = "over_budget"  # tier 1 not tried, budget exhausted, static answer


@dataclass(frozen=True, slots=True)
class EngineResult:
    response: GeneratedResponse
    source: Source
    # Tokens the model spent on this request, including an answer that was rejected.
    tokens_used: int = 0

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


class BudgetLike(Protocol):
    async def allow(self, request: CapturedRequest, tier: int, est_tokens: int = ...) -> bool: ...
    async def settle(
        self, request: CapturedRequest, tier: int, *, estimated: int, actual: int
    ) -> None: ...


class ResponseEngine:
    def __init__(
        self, *, cache: CacheLike, model: ModelLike, budget: BudgetLike | None = None
    ) -> None:
        self.cache = cache
        self.model = model
        # None means no limit; production wires a BudgetManager.
        self.budget = budget

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

        messages = build_messages(persona_prompt=persona_prompt, request=request)
        estimated = estimate_tokens(messages, RESPONSE_MAX_TOKENS)
        if self.budget is not None and not await self.budget.allow(request, TIER1, estimated):
            return EngineResult(fallback(), Source.OVER_BUDGET)

        generated, tokens = await self._generate(request, messages, estimated)
        if generated is None:
            return EngineResult(fallback(), Source.FALLBACK, tokens)

        await self.cache.set(signature, generated)
        return EngineResult(generated, Source.MODEL, tokens)

    async def _generate(
        self, request: CapturedRequest, messages: list[Message], estimated: int
    ) -> tuple[GeneratedResponse | None, int]:
        """The validated answer (None on failure) and the tokens spent getting it.

        ``estimated`` is what the budget was charged before the call; it is corrected
        here to the real usage.
        """
        try:
            completion = await self.model.complete(
                messages, max_tokens=RESPONSE_MAX_TOKENS, json_mode=True
            )
        except LLMError as exc:
            observe_llm_failure(_failure_reason(exc))
            logger.warning("tier1_failed", error=type(exc).__name__)
            # A timeout keeps its charge: the model was busy for the whole wait. An
            # endpoint that was never reached cost nothing, so that is refunded.
            if isinstance(exc, LLMUnavailable):
                await self._settle(request, estimated, 0)
            return None, 0
        await self._settle(request, estimated, completion.total_tokens)
        try:
            return GeneratedResponse.model_validate_json(completion.text), completion.total_tokens
        except ValidationError:
            observe_llm_failure("invalid_output")
            # Details are not logged: they quote attacker-influenced model output.
            logger.warning("tier1_output_invalid", truncated=completion.truncated)
            return None, completion.total_tokens

    async def _settle(self, request: CapturedRequest, estimated: int, actual: int) -> None:
        if self.budget is not None:
            await self.budget.settle(request, TIER1, estimated=estimated, actual=actual)


def _failure_reason(exc: LLMError) -> str:
    """Bounded metric label for a model error."""
    if isinstance(exc, LLMTimeout):
        return "timeout"
    if isinstance(exc, LLMUnavailable):
        return "unavailable"
    if isinstance(exc, LLMBadResponse):
        return "bad_response"
    return "other"
