"""Prometheus metrics for the request path.

Defined once at import and recorded into prometheus_client's default registry,
which the internal server exposes on /metrics. Labels are bounded: a handful of
personas, three tiers and HTTP status codes (100-599), so an attacker cannot
inflate the number of series.
"""

from prometheus_client import Counter, Histogram

_LATENCY_BUCKETS = (0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 3, 5, 8)

REQUESTS = Counter(
    "mirage_requests",
    "Requests answered, by persona, response tier and status code.",
    ["persona", "tier", "status"],
)
REQUEST_DURATION = Histogram(
    "mirage_request_duration_seconds",
    "Time from request body received to response finished, by persona and response tier.",
    ["persona", "tier"],
    buckets=_LATENCY_BUCKETS,
)

LLM_FAILURES = Counter(
    "mirage_llm_failures",
    "Tier 1 model calls that produced no usable answer, by reason: timeout, "
    "unavailable (connection or HTTP error), bad_response (malformed API reply) "
    "invalid_output (model text failed GeneratedResponse validation) or "
    "prompt_leak (a valid answer that repeated the system prompt).",
    ["reason"],
)
FALLBACKS = Counter(
    "mirage_fallbacks",
    "Requests answered with the static fallback because the model failed.",
)


def observe_fallback() -> None:
    FALLBACKS.inc()


def observe_llm_failure(reason: str) -> None:
    LLM_FAILURES.labels(reason=reason).inc()
    observe_fallback()


def observe_request(*, persona: str, tier: int, status: int | None, duration_s: float) -> None:
    """Record one answered request. ``status`` is None if no response was started."""
    REQUESTS.labels(persona=persona, tier=str(tier), status=str(status or "none")).inc()
    REQUEST_DURATION.labels(persona=persona, tier=str(tier)).observe(duration_s)
