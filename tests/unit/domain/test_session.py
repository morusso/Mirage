import pytest
from pydantic import ValidationError

from domain.session import SessionSignals


def test_initial_signals_describe_a_session_that_just_started() -> None:
    signals = SessionSignals.initial()

    assert signals.request_count == 1
    assert signals.mean_interval_s == 0.0
    assert signals.known_tool is None
    assert signals.classification is None
    assert signals.interest_score == 0.0


def test_signals_are_immutable() -> None:
    signals = SessionSignals.initial()

    with pytest.raises(ValidationError):
        signals.interest_score = 1.0


@pytest.mark.parametrize(
    "field, value",
    [
        ("request_count", 0),
        ("path_diversity", 1.5),
        ("path_diversity", -0.1),
        ("mean_interval_s", -1.0),
        ("interest_score", 1.01),
        ("interest_score", float("nan")),
        ("known_tool", ""),
        ("known_tool", "Sqlmap; DROP"),
        ("classification", "x" * 65),
    ],
)
def test_out_of_range_values_are_rejected(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        SessionSignals.model_validate({field: value})


def test_unknown_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        SessionSignals.model_validate({"unexpected": 1})


def test_a_full_signal_set_round_trips() -> None:
    signals = SessionSignals(
        request_count=42,
        path_diversity=0.95,
        mean_interval_s=0.02,
        known_tool="sqlmap",
        classification="bot",
        interest_score=0.1,
    )

    assert SessionSignals.model_validate_json(signals.model_dump_json()) == signals
