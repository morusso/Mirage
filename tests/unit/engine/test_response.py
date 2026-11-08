import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from app.engine.response import MAX_BODY_CHARS, MAX_HEADERS, GeneratedResponse


def _make(**kw: object) -> GeneratedResponse:
    return GeneratedResponse.model_validate({"status_code": 200, **kw})


def test_minimal_response_has_empty_headers_and_body() -> None:
    r = _make()

    assert (r.status_code, r.headers, r.body) == (200, {}, "")


def test_round_trips_through_json() -> None:
    r = _make(headers={"Content-Type": "text/html"}, body="<p>hi</p>")

    assert GeneratedResponse.model_validate_json(r.model_dump_json()) == r


@pytest.mark.parametrize("status", [0, 99, 100, 101, 199, 600, 1000, -1])
def test_status_outside_final_responses_is_rejected(status: int) -> None:
    with pytest.raises(ValidationError):
        _make(status_code=status)


@pytest.mark.parametrize("status", [200, 301, 404, 500, 599])
def test_final_statuses_are_accepted(status: int) -> None:
    assert _make(status_code=status).status_code == status


def test_missing_status_is_rejected() -> None:
    with pytest.raises(ValidationError):
        GeneratedResponse.model_validate({"headers": {}, "body": "x"})


def test_body_over_the_limit_is_rejected() -> None:
    _make(body="x" * MAX_BODY_CHARS)
    with pytest.raises(ValidationError):
        _make(body="x" * (MAX_BODY_CHARS + 1))


def test_extra_fields_are_dropped_not_fatal() -> None:
    r = _make(body="x", explanation="as an AI...", state_updates=[{"op": "x"}])

    assert not hasattr(r, "explanation")
    assert "explanation" not in r.model_dump()


def test_header_names_are_lowercased() -> None:
    assert _make(headers={"X-Request-Id": "abc"}).headers == {"x-request-id": "abc"}


def test_numeric_header_values_are_stringified() -> None:
    assert _make(headers={"X-RateLimit-Remaining": 59, "X-Ratio": 0.5}).headers == {
        "x-ratelimit-remaining": "59",
        "x-ratio": "0.5",
    }


@pytest.mark.parametrize("value", [True, None, ["a"], {"a": 1}])
def test_other_header_value_types_are_rejected(value: object) -> None:
    with pytest.raises(ValidationError):
        _make(headers={"X-A": value})


@pytest.mark.parametrize(
    "name",
    ["", "bad name", "bad:name", "new\nline", "x\r", "naïve", "a" * 65, "(paren)", "a/b"],
)
def test_invalid_header_names_are_rejected(name: str) -> None:
    with pytest.raises(ValidationError):
        _make(headers={name: "v"})


@pytest.mark.parametrize(
    "value",
    [
        "a\r\nSet-Cookie: pwned=1",  # response splitting
        "a\nb",
        "a\x00b",
        "a\x7fb",
        "zażółć",  # not encodable as latin-1 / ASCII
        "v" * 2049,
    ],
)
def test_unsafe_header_values_are_rejected(value: str) -> None:
    with pytest.raises(ValidationError):
        _make(headers={"X-A": value})


def test_tab_and_space_are_allowed_in_values() -> None:
    assert _make(headers={"X-A": "a b\tc"}).headers == {"x-a": "a b\tc"}


def test_server_owned_headers_are_dropped() -> None:
    r = _make(
        headers={
            "Content-Length": "3",
            "Transfer-Encoding": "chunked",
            "Connection": "close",
            "Server": "Apache",
            "X-Powered-By": "PHP",
            "Date": "now",
            "Content-Type": "text/plain",
        }
    )

    assert r.headers == {"content-type": "text/plain"}


def test_too_many_headers_are_rejected() -> None:
    _make(headers={f"x-{i}": "v" for i in range(MAX_HEADERS)})
    with pytest.raises(ValidationError):
        _make(headers={f"x-{i}": "v" for i in range(MAX_HEADERS + 1)})


def test_duplicate_header_names_differing_in_case_are_rejected() -> None:
    with pytest.raises(ValidationError):
        _make(headers={"X-A": "1", "x-a": "2"})


@pytest.mark.parametrize("status", [204, 304])
def test_bodyless_statuses_lose_their_body(status: int) -> None:
    assert _make(status_code=status, body="oops").body == ""


@given(
    status=st.integers(),
    headers=st.dictionaries(st.text(max_size=80), st.text(max_size=80), max_size=40),
    body=st.text(max_size=200),
)
def test_validation_never_raises_anything_but_validation_error(
    status: int, headers: dict[str, str], body: str
) -> None:
    try:
        r = GeneratedResponse.model_validate(
            {"status_code": status, "headers": headers, "body": body}
        )
    except ValidationError:
        return
    # Whatever got through is safe to put on the wire.
    assert 200 <= r.status_code <= 599
    for name, value in r.headers.items():
        assert name.isascii() and value.isascii()
        assert "\r" not in name + value and "\n" not in name + value
