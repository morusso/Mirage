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
    monkeypatch.setenv("MIRAGE_CANARY_KEY", "k" * 32)
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


def test_trusted_proxies_default_to_none() -> None:
    assert Settings().trusted_proxies == []


def test_trusted_proxies_are_parsed_from_json_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MIRAGE_TRUSTED_PROXIES", '["172.16.0.0/12", "fd00::/8"]')

    networks = [str(n) for n in Settings().trusted_proxies]

    assert networks == ["172.16.0.0/12", "fd00::/8"]


def test_database_url_is_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MIRAGE_DATABASE_URL", "postgresql+asyncpg://u:s3cret@db/mirage")

    settings = Settings()

    assert settings.database_url.get_secret_value().endswith("@db/mirage")
    assert "s3cret" not in repr(settings)


def test_tier1_is_off_by_default() -> None:
    assert Settings().tier1_enabled is False


def test_tier1_flag_is_read_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MIRAGE_TIER1_ENABLED", "true")

    assert Settings().tier1_enabled is True


def test_prod_refuses_the_public_default_canary_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MIRAGE_ENVIRONMENT", "prod")

    with pytest.raises(ValidationError, match="MIRAGE_CANARY_KEY"):
        Settings()


def test_prod_accepts_a_private_canary_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MIRAGE_ENVIRONMENT", "prod")
    monkeypatch.setenv("MIRAGE_CANARY_KEY", "k" * 32)

    assert Settings().canary_key.get_secret_value() == "k" * 32
