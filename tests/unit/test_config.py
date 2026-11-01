from pathlib import Path

import pytest
from pydantic import ValidationError

from app.config import Settings


@pytest.fixture(autouse=True)
def _isolated_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)


def test_defaults() -> None:
    settings = Settings()

    assert settings.environment == "dev"
    assert settings.log_level == "INFO"


def test_reads_values_with_mirage_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MIRAGE_ENVIRONMENT", "prod")
    monkeypatch.setenv("MIRAGE_LOG_LEVEL", "DEBUG")

    settings = Settings()

    assert settings.environment == "prod"
    assert settings.log_level == "DEBUG"


def test_ignores_variables_without_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "prod")

    assert Settings().environment == "dev"


def test_rejects_invalid_log_level(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MIRAGE_LOG_LEVEL", "LOUD")

    with pytest.raises(ValidationError):
        Settings()
