"""BudgetManager: how many model tokens one source may spend per window.

A budget protects the model's capacity (tier 1) and money (tier 2) without ever
blocking the attacker: a request over budget is not refused, it is answered from tier 0
(see ResponseEngine). Tokens, not calls, are counted, because a call's cost is its size.

A request is charged to several dimensions at once (its IP, its /24 or /64 subnet and
the honeypot as a whole) and must fit all of them, so one scanner cannot take the model
and neither can a hosting provider that rotates addresses. The check is atomic, see
``budget_script``.
"""

import asyncio
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from ipaddress import ip_address

import structlog
from redis.asyncio import Redis
from redis.exceptions import RedisError

from app.engine.budget_script import SlidingWindowBudget
from app.engine.llm_client import Message
from domain.captured_request import CapturedRequest
from domain.network import subnet_of

logger = structlog.get_logger()

KEY_PREFIX = "mirage:budget:"
# Reported when Redis cannot answer: the budget fails closed, so tier 0 answers.
UNAVAILABLE = "unavailable"


# Rough size of English or JSON text in tokens. A guess is enough: the charge is
# corrected with the real usage once the model has answered.
CHARS_PER_TOKEN = 4


def estimate_tokens(messages: list[Message], max_tokens: int) -> int:
    """Worst-case cost of a call: the prompt plus the whole completion allowance.

    Charging the worst case up front means concurrent requests cannot jointly overspend
    while their answers are still being generated; ``BudgetManager.settle`` refunds
    what the model did not use.
    """
    prompt_chars = sum(len(m.content) for m in messages)
    return -(-prompt_chars // CHARS_PER_TOKEN) + max_tokens


@dataclass(frozen=True, slots=True)
class TierBudget:
    """Tokens per window for each dimension; 0 or less means unlimited."""

    ip: int
    subnet: int
    # Circuit breaker for the whole honeypot: caps the model's total load however many
    # sources take part in a coordinated burst.
    total: int


# Tier 1 default: about 6 calls of ~300 tokens a minute per IP, 3x that per subnet and
# 50 calls a minute in total.
DEFAULT_LIMITS: Mapping[int, TierBudget] = {1: TierBudget(ip=2_000, subnet=6_000, total=15_000)}


class BudgetManager:
    def __init__(
        self,
        redis: Redis,
        *,
        limits: Mapping[int, TierBudget] = DEFAULT_LIMITS,
        window_s: int = 60,
        timeout_s: float = 0.2,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.limits = limits
        self.timeout_s = timeout_s
        self._clock = clock
        self._window = SlidingWindowBudget(redis, window_s=window_s)

    async def allow(self, request: CapturedRequest, tier: int, est_tokens: int = 300) -> bool:
        """Charge ``est_tokens`` to the request's budgets; False if any has no room."""
        return await self.refused_by(request, tier, est_tokens) is None

    async def refused_by(
        self, request: CapturedRequest, tier: int, est_tokens: int = 300
    ) -> str | None:
        """Like ``allow`` but names the dimension that refused (``ip``, ``subnet``, or
        ``global``, or ``unavailable`` when Redis failed), or None if the request was charged.
        """
        dimensions = self._dimensions(request, tier)
        try:
            async with asyncio.timeout(self.timeout_s):
                failed = await self._window.check_and_consume(
                    [key for _, key, _ in dimensions],
                    [limit for _, _, limit in dimensions],
                    est_tokens,
                    now_ms=int(self._clock() * 1000),
                )
        except (RedisError, OSError, TimeoutError) as exc:
            logger.warning("budget_check_failed", error=type(exc).__name__)
            return UNAVAILABLE
        return None if failed is None else dimensions[failed][0]

    def _dimensions(self, request: CapturedRequest, tier: int) -> list[tuple[str, str, int]]:
        """(name, Redis key, limit) of every dimension a request is charged to."""
        budget = self.limits.get(tier)
        if budget is None:
            raise KeyError(f"no budget configured for tier {tier}")
        # The address is normalised, so IPv6 spellings of one host share a key.
        ip = ip_address(request.ip)
        return [
            ("ip", f"{KEY_PREFIX}{tier}:ip:{ip}", budget.ip),
            ("subnet", f"{KEY_PREFIX}{tier}:net:{subnet_of(ip)}", budget.subnet),
            ("global", f"{KEY_PREFIX}{tier}:global", budget.total),
        ]

    async def settle(
        self, request: CapturedRequest, tier: int, *, estimated: int, actual: int
    ) -> None:
        """Replace the estimate charged by ``allow`` with the tokens really used.

        Refunds when the model used less, charges the difference when it used more
        (the call already happened, so this can push a dimension over its limit; the
        next ``allow`` then refuses). Never raises: bookkeeping must not break an answer.
        """
        delta = actual - estimated
        if delta == 0:
            return
        keys = [key for _, key, _ in self._dimensions(request, tier)]
        try:
            async with asyncio.timeout(self.timeout_s):
                await self._window.adjust(keys, delta)
        except (RedisError, OSError, TimeoutError) as exc:
            logger.warning("budget_settle_failed", error=type(exc).__name__)
