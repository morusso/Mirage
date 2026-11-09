from app.engine.budget import estimate_tokens
from app.engine.llm_client import Message


def test_estimate_is_prompt_tokens_plus_the_completion_allowance() -> None:
    messages = [Message("system", "a" * 400), Message("user", "b" * 100)]

    assert estimate_tokens(messages, 512) == 125 + 512


def test_partial_token_rounds_up() -> None:
    assert estimate_tokens([Message("user", "abcde")], 0) == 2


def test_empty_prompt_costs_only_the_allowance() -> None:
    assert estimate_tokens([], 300) == 300
