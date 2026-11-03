import re
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import ClassVar
from uuid import uuid4

import pytest

from domain.captured_request import CapturedRequest
from workers.detector.rules import (
    MAX_EXCERPT_CHARS,
    MAX_PART_CHARS,
    Inspection,
    Location,
    RegexRule,
    Rule,
    RuleRegistry,
    Severity,
)


def _request(
    *,
    path: str = "/",
    query: str = "",
    body: str = "",
    headers: list[tuple[str, str]] | None = None,
) -> CapturedRequest:
    return CapturedRequest(
        ts=datetime(2026, 1, 1, tzinfo=UTC),
        session_id=uuid4(),
        world_id="w",
        ip=ip_address("203.0.113.9"),
        method="GET",
        path=path,
        query=query,
        body_excerpt=body,
        headers=headers or [],
    )


class Contains(Rule):
    category = "test"
    severity = Severity.LOW

    def __init__(self, name: str, needle: str) -> None:
        self.name = name
        self.needle = needle

    def match(self, inspection: Inspection) -> str | None:
        for part in inspection.parts:
            if self.needle in part.text:
                return part.text
        return None


class Boom(Rule):
    name = "test.boom"
    category = "test"
    severity = Severity.LOW

    def match(self, inspection: Inspection) -> str | None:
        raise RuntimeError("buggy rule")


class BodyOnly(RegexRule):
    name = "test.body_only"
    category = "test"
    severity = Severity.MEDIUM
    patterns: ClassVar = (re.compile(r"evil\d+"),)
    locations: ClassVar = (Location.BODY,)


# --- normalization -----------------------------------------------------------


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("q=%27+OR+1%3D1", "q=' OR 1=1"),  # percent and plus
        ("q=%2527", "q='"),  # double encoding
        ("q=%252527", "q='"),  # triple encoding
        ("q=a%00b", "q=ab"),  # NUL stripped
        ("q=%25252527", "q=%27"),  # deeper than the limit stops, never loops
    ],
)
def test_query_is_decoded_repeatedly(query: str, expected: str) -> None:
    inspection = Inspection(_request(query=query))

    assert list(inspection.texts([Location.QUERY])) == [expected]


def test_parts_are_labelled_and_empty_ones_dropped() -> None:
    inspection = Inspection(
        _request(
            path="/a%2Fb", query="", body="x", headers=[("User-Agent", "sqlmap"), ("X-Empty", "")]
        )
    )

    assert [(p.location, p.text) for p in inspection.parts] == [
        (Location.PATH, "/a/b"),
        (Location.BODY, "x"),
        (Location.HEADER, "sqlmap"),
    ]


def test_header_names_are_not_inspected() -> None:
    inspection = Inspection(_request(headers=[("X-Union-Select", "ok")]))

    assert list(inspection.texts([Location.HEADER])) == ["ok"]


def test_parts_are_capped() -> None:
    inspection = Inspection(_request(body="a" * (MAX_PART_CHARS * 3)))

    (body,) = inspection.texts([Location.BODY])
    assert len(body) == MAX_PART_CHARS


def test_texts_filters_by_location() -> None:
    inspection = Inspection(_request(path="/p", query="q=1", body="b"))

    assert list(inspection.texts([Location.QUERY, Location.BODY])) == ["q=1", "b"]


# --- rules -------------------------------------------------------------------


def test_regex_rule_matches_only_its_locations() -> None:
    rule = BodyOnly()

    assert rule.match(Inspection(_request(body="..evil42.."))) == "evil42"
    assert rule.match(Inspection(_request(query="x=evil42"))) is None


# --- registry ----------------------------------------------------------------


def test_registry_returns_detections_in_registration_order() -> None:
    registry = RuleRegistry()
    registry.register(Contains("test.second", "bb"))
    registry.register(Contains("test.first", "aa"))

    detections = registry.evaluate(_request(query="aa bb"))

    assert [d.rule for d in detections] == ["test.second", "test.first"]
    assert detections[0].category == "test"
    assert detections[0].severity is Severity.LOW


def test_registry_gives_no_detections_for_clean_request() -> None:
    registry = RuleRegistry()
    registry.register(Contains("test.first", "aa"))

    assert registry.evaluate(_request(path="/api/v1/products")) == []


def test_registry_truncates_excerpts() -> None:
    registry = RuleRegistry()
    registry.register(Contains("test.first", "aa"))

    (detection,) = registry.evaluate(_request(body="aa" + "x" * 5000))

    assert len(detection.matched_excerpt) == MAX_EXCERPT_CHARS


def test_failing_rule_is_skipped_and_others_still_run() -> None:
    registry = RuleRegistry()
    registry.register(Boom())
    registry.register(Contains("test.first", "aa"))

    assert [d.rule for d in registry.evaluate(_request(query="aa"))] == ["test.first"]


def test_duplicate_names_are_rejected() -> None:
    registry = RuleRegistry()
    registry.register(Contains("test.first", "aa"))

    with pytest.raises(ValueError, match="duplicate"):
        registry.register(Contains("test.first", "bb"))


@pytest.mark.parametrize("name", ["", "nodot", "Test.Upper", "test.", ".x", "a b.c", "a.b-c"])
def test_invalid_rule_names_are_rejected(name: str) -> None:
    with pytest.raises(ValueError, match="invalid rule name"):
        RuleRegistry().register(Contains(name, "x"))


def test_invalid_category_is_rejected() -> None:
    class BadCategory(Contains):
        category = "Not A Slug"

    with pytest.raises(ValueError, match="invalid category"):
        RuleRegistry().register(BadCategory("test.bad", "x"))


def test_severity_values_match_the_database_constraint() -> None:
    assert {s.value for s in Severity} == {"low", "medium", "high", "critical"}
