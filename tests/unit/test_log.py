import json

import pytest
import structlog

from app.log import configure_logging


def test_emits_json_with_level_and_timestamp(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("INFO")

    structlog.get_logger().info("hello", persona="fake_api")

    record = json.loads(capsys.readouterr().out)
    assert record["event"] == "hello"
    assert record["persona"] == "fake_api"
    assert record["level"] == "info"
    assert record["timestamp"].endswith("Z")


def test_filters_messages_below_configured_level(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("WARNING")
    logger = structlog.get_logger()

    logger.info("ignored")
    logger.warning("kept")

    lines = capsys.readouterr().out.splitlines()
    assert [json.loads(line)["event"] for line in lines] == ["kept"]


def test_includes_exception_info(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("INFO")

    try:
        raise ValueError("boom")
    except ValueError:
        structlog.get_logger().exception("failed")

    record = json.loads(capsys.readouterr().out)
    assert "ValueError: boom" in record["exception"]
