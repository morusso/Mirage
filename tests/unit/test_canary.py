import re

import pytest

from app.engine.canary import CanaryKind, canaries_for, canary_token

KEY = b"test-canary-key"


def test_token_is_stable_for_world_kind_and_key() -> None:
    assert canary_token("w_a", CanaryKind.DB_PASSWORD, KEY) == canary_token(
        "w_a", CanaryKind.DB_PASSWORD, KEY
    )


def test_tokens_differ_between_worlds_kinds_and_keys() -> None:
    base = canary_token("w_a", CanaryKind.DB_PASSWORD, KEY)

    assert canary_token("w_b", CanaryKind.DB_PASSWORD, KEY) != base
    assert canary_token("w_a", CanaryKind.SMTP_PASSWORD, KEY) != base
    assert canary_token("w_a", CanaryKind.DB_PASSWORD, b"other-key") != base


def test_all_tokens_of_many_worlds_are_unique() -> None:
    tokens = [token for n in range(200) for token in canaries_for(f"w_{n}", KEY).values()]

    assert len(tokens) == len(set(tokens))


@pytest.mark.parametrize(
    ("kind", "pattern"),
    [
        (CanaryKind.DB_PASSWORD, r"[a-zA-Z2-9]{24}"),
        (CanaryKind.REDIS_PASSWORD, r"[0-9a-f]{32}"),
        (CanaryKind.JWT_SECRET, r"[A-Za-z0-9_-]{43}"),
        (CanaryKind.AWS_ACCESS_KEY_ID, r"SN[A-Z2-9]{18}"),
        (CanaryKind.AWS_SECRET_ACCESS_KEY, r"[A-Za-z2-9/]{40}"),
        (CanaryKind.GIT_TOKEN, r"[0-9a-f]{40}"),
    ],
)
def test_token_shape(kind: CanaryKind, pattern: str) -> None:
    assert re.fullmatch(pattern, canary_token("w_a", kind, KEY))


def test_tokens_do_not_look_like_real_provider_keys() -> None:
    for token in canaries_for("w_a", KEY).values():
        assert not token.startswith(("AKIA", "ASIA", "sk_", "ghp_", "xox"))


def test_every_kind_has_a_canary() -> None:
    assert set(canaries_for("w_a", KEY)) == set(CanaryKind)


def test_empty_key_is_rejected() -> None:
    with pytest.raises(ValueError, match="empty"):
        canary_token("w_a", CanaryKind.DB_PASSWORD, b"")
