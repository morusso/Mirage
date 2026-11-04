"""Every detector family together, run against a corpus of labelled requests.

The per-family test files check each rule in isolation. This one registers all of
them in one registry, as the detector worker will, and checks what a real request
sets off: the expected categories and nothing else. It catches rules that collide
on a name, and families that fire on each other's traffic.

The corpus is ``tests/data/detector_corpus.json``: one entry per request with the
set of categories it must trigger (empty for ordinary traffic). Add a case there
whenever a missed attack or a false alarm shows up in real data.
"""

import json
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from domain.captured_request import CapturedRequest
from workers.detector import cmdi, log4shell, scanners, sqli, ssti, traversal, xss
from workers.detector.rules import RuleRegistry

CORPUS_PATH = Path(__file__).resolve().parents[1] / "data" / "detector_corpus.json"
FAMILIES = (sqli, xss, ssti, traversal, cmdi, log4shell, scanners)

CORPUS: list[dict[str, Any]] = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))


def _to_request(spec: dict[str, Any]) -> CapturedRequest:
    return CapturedRequest(
        ts=datetime(2026, 1, 1, tzinfo=UTC),
        session_id=uuid4(),
        world_id="w",
        ip=ip_address("203.0.113.9"),
        method="GET",
        path=spec.get("path", "/"),
        query=spec.get("query", ""),
        body_excerpt=spec.get("body", ""),
        headers=[(name, value) for name, value in spec.get("headers", [])],
    )


@pytest.fixture(scope="module")
def registry() -> RuleRegistry:
    registry = RuleRegistry()
    for family in FAMILIES:
        for rule in family.RULES:
            registry.register(rule)  # raises if two families share a rule name
    return registry


@pytest.mark.parametrize("case", CORPUS, ids=[case["id"] for case in CORPUS])
def test_request_triggers_exactly_the_expected_categories(
    registry: RuleRegistry, case: dict[str, Any]
) -> None:
    fired = {d.category for d in registry.evaluate(_to_request(case["request"]))}

    assert fired == set(case["expect"])


def test_corpus_ids_are_unique() -> None:
    ids = [case["id"] for case in CORPUS]

    assert len(ids) == len(set(ids))


def test_every_family_has_attack_cases() -> None:
    covered = {category for case in CORPUS for category in case["expect"]}

    assert covered == {rule.category for family in FAMILIES for rule in family.RULES}


def test_corpus_includes_clean_traffic() -> None:
    clean = [case for case in CORPUS if not case["expect"]]

    assert len(clean) >= 10


def test_every_rule_is_exercised_by_the_corpus(registry: RuleRegistry) -> None:
    exercised = {d.rule for case in CORPUS for d in registry.evaluate(_to_request(case["request"]))}

    assert {rule.name for rule in registry.rules} - exercised == set()
