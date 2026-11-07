"""Async client for an OpenAI-compatible chat endpoint (Ollama, vLLM, hosted APIs).

One instance per tier, built from that tier's ``TierConfig``. Every failure comes out
as an ``LLMError`` subclass, so the engine has a single thing to catch before falling
back to tier 0. Calls have a hard deadline (``TierConfig.timeout_s``) and are never
retried: a retry would blow the latency budget, and the fallback is cheaper.

Message text is attacker-influenced, so it is never logged here.
"""

import asyncio
from dataclasses import dataclass
from typing import Literal, cast

import openai
from openai import AsyncOpenAI, Omit, omit
from openai.types.chat import ChatCompletionMessageParam
from openai.types.shared_params import ResponseFormatJSONObject

from app.engine.llm_settings import TierConfig

# Ollama and vLLM ignore the key; the SDK refuses to start without one.
_PLACEHOLDER_API_KEY = "unused"


class LLMError(Exception):
    """The model did not give a usable answer. Base for everything below."""


class LLMTimeout(LLMError):
    """No answer within the tier's deadline."""


class LLMUnavailable(LLMError):
    """The endpoint could not be reached or answered with an error status."""


class LLMBadResponse(LLMError):
    """The endpoint answered, but not with a chat completion we can use."""


@dataclass(frozen=True, slots=True)
class Message:
    role: Literal["system", "user", "assistant"]
    content: str


@dataclass(frozen=True, slots=True)
class Completion:
    text: str
    prompt_tokens: int
    completion_tokens: int
    # True when the model hit max_tokens: structured output is probably cut off.
    truncated: bool

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class LLMClient:
    def __init__(self, config: TierConfig, *, client: AsyncOpenAI | None = None) -> None:
        self.config = config
        self._client = client or AsyncOpenAI(
            base_url=config.base_url,
            api_key=_PLACEHOLDER_API_KEY,
            timeout=config.timeout_s,
            max_retries=0,
        )

    async def complete(
        self,
        messages: list[Message],
        *,
        max_tokens: int | None = None,
        temperature: float = 0.0,
        json_mode: bool = False,
    ) -> Completion:
        """One chat completion. ``max_tokens`` can only lower the tier's limit.

        Temperature 0 by default: the same request should give the same answer.
        ``json_mode`` asks the server for a JSON object; the output still has to be
        validated by the caller.
        """
        limit = min(max_tokens or self.config.max_tokens, self.config.max_tokens)
        params = cast(
            list[ChatCompletionMessageParam],
            [{"role": m.role, "content": m.content} for m in messages],
        )
        response_format: ResponseFormatJSONObject | Omit = (
            {"type": "json_object"} if json_mode else omit
        )
        try:
            # The SDK enforces its own timeout; this is the backstop for the whole call.
            async with asyncio.timeout(self.config.timeout_s):
                response = await self._client.chat.completions.create(
                    model=self.config.model,
                    messages=params,
                    max_tokens=limit,
                    temperature=temperature,
                    stream=False,
                    response_format=response_format,
                )
        except (TimeoutError, openai.APITimeoutError) as exc:
            raise LLMTimeout(f"no answer within {self.config.timeout_s}s") from exc
        except openai.APIStatusError as exc:
            raise LLMUnavailable(f"endpoint answered HTTP {exc.status_code}") from exc
        except openai.APIConnectionError as exc:
            raise LLMUnavailable("endpoint unreachable") from exc
        except (openai.OpenAIError, ValueError) as exc:
            # ValueError: the SDK lets a body that is not JSON (or not a completion)
            # escape as json/pydantic errors rather than as its own exception type.
            raise LLMBadResponse(type(exc).__name__) from exc

        if not response.choices:
            raise LLMBadResponse("no choices in the response")
        choice = response.choices[0]
        text = choice.message.content
        if not text:
            raise LLMBadResponse("empty message")
        usage = response.usage
        return Completion(
            text=text,
            prompt_tokens=usage.prompt_tokens if usage else 0,
            completion_tokens=usage.completion_tokens if usage else 0,
            truncated=choice.finish_reason == "length",
        )

    async def aclose(self) -> None:
        await self._client.close()
