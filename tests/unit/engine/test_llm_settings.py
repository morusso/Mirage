import pytest
from pydantic import ValidationError

from app.engine.llm_settings import LLMSettings, TierConfig


def _tier(**kw: object) -> TierConfig:
    base: dict[str, object] = {
        "base_url": "http://ollama:11434/v1",
        "model": "m",
        "timeout_s": 3.0,
        "max_tokens": 512,
    }
    return TierConfig(**{**base, **kw})  # type: ignore[arg-type]


def test_defaults_point_at_the_compose_ollama_service() -> None:
    local = LLMSettings(_env_file=None).local  # type: ignore[call-arg]

    assert local.base_url == "http://ollama:11434/v1"
    assert local.model == "qwen2.5:7b"
    assert local.timeout_s == 3.0
    assert local.max_tokens == 512


def test_environment_overrides_single_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MIRAGE_LLM_LOCAL__MODEL", "llama3.1:8b")
    monkeypatch.setenv("MIRAGE_LLM_LOCAL__TIMEOUT_S", "2.5")

    local = LLMSettings(_env_file=None).local  # type: ignore[call-arg]

    assert (local.model, local.timeout_s) == ("llama3.1:8b", 2.5)
    assert local.base_url == "http://ollama:11434/v1"  # untouched fields keep their default


def test_environment_can_replace_the_whole_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MIRAGE_LLM_LOCAL__BASE_URL", "http://vllm:8000/v1/")

    local = LLMSettings(_env_file=None).local  # type: ignore[call-arg]

    assert local.base_url == "http://vllm:8000/v1"


def test_unrelated_mirage_variables_are_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MIRAGE_LOG_LEVEL", "DEBUG")

    LLMSettings(_env_file=None)  # type: ignore[call-arg]


@pytest.mark.parametrize(
    "bad",
    [
        {"base_url": "ollama:11434/v1"},
        {"base_url": "ftp://ollama/v1"},
        {"base_url": "http://"},
        {"model": ""},
        {"timeout_s": 0},
        {"timeout_s": 61},
        {"max_tokens": 0},
        {"max_tokens": 100_000},
    ],
)
def test_invalid_tier_config_is_rejected(bad: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        _tier(**bad)


def test_tier_config_is_immutable() -> None:
    with pytest.raises(ValidationError):
        _tier().model = "other"
