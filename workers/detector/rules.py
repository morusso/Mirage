"""Detection rule interface, request normalization and rule registry.

Rules look for attack payloads in a request. They run in the detector worker, off
the request path, on text the attacker fully controls: a rule must be cheap, must
never trust that text, and must use linear-time regular expressions only (no
nested quantifiers) so a crafted payload cannot make the worker spin.
"""

import re
from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar
from urllib.parse import unquote_plus

import structlog

from domain.captured_request import CapturedRequest

logger = structlog.get_logger()

MAX_PART_CHARS = 8192  # inspected per location; the rest is ignored
MAX_EXCERPT_CHARS = 200  # stored per detection
MAX_DECODE_ROUNDS = 3  # %2527 -> %27 -> ' : stop at a fixed point or after this many

_SLUG = re.compile(r"^[a-z0-9_]+$")
_RULE_NAME = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_]+)+$")  # e.g. "sqli.union"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Location(StrEnum):
    PATH = "path"
    QUERY = "query"
    BODY = "body"
    HEADER = "header"


@dataclass(frozen=True, slots=True)
class Detection:
    rule: str
    category: str
    severity: Severity
    matched_excerpt: str  # attacker-controlled: escape on display


@dataclass(frozen=True, slots=True)
class Part:
    location: Location
    text: str


class Inspection:
    """The text of one request in the forms rules should look at.

    Path, query and body are URL-decoded repeatedly (attackers double-encode to slip
    past filters) and stripped of NUL bytes. Headers are inspected as values only,
    decoded the same way. Every part is capped at ``MAX_PART_CHARS``.
    """

    def __init__(self, request: CapturedRequest) -> None:
        parts = [
            Part(Location.PATH, _normalize(request.path)),
            Part(Location.QUERY, _normalize(request.query)),
            Part(Location.BODY, _normalize(request.body_excerpt)),
            *(Part(Location.HEADER, _normalize(value)) for _, value in request.headers),
        ]
        self.parts: tuple[Part, ...] = tuple(p for p in parts if p.text)
        self.request = request

    def texts(self, locations: Iterable[Location]) -> Iterator[str]:
        wanted = set(locations)
        return (part.text for part in self.parts if part.location in wanted)


def _normalize(raw: str) -> str:
    text = raw[:MAX_PART_CHARS]
    for _ in range(MAX_DECODE_ROUNDS):
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded
    return text.replace("\x00", "")[:MAX_PART_CHARS]


class Rule(ABC):
    """One check. Subclasses set the class attributes and implement ``match``."""

    name: str  # unique, "<family>.<variant>"
    category: str  # coarse grouping used by dashboards, e.g. "sqli"
    severity: Severity

    @abstractmethod
    def match(self, inspection: Inspection) -> str | None:
        """The offending text if the request matches, otherwise None."""


class RegexRule(Rule):
    """A rule that fires when any pattern matches in any of the chosen locations."""

    patterns: ClassVar[tuple[re.Pattern[str], ...]]
    locations: ClassVar[tuple[Location, ...]] = tuple(Location)

    def match(self, inspection: Inspection) -> str | None:
        for text in inspection.texts(self.locations):
            for pattern in self.patterns:
                if found := pattern.search(text):
                    return found.group(0)
        return None


class RuleRegistry:
    def __init__(self) -> None:
        self._rules: dict[str, Rule] = {}

    def register(self, rule: Rule) -> Rule:
        """Add a rule; returns it so modules can write ``RULE = registry.register(...)``."""
        if not _RULE_NAME.match(rule.name):
            raise ValueError(f"invalid rule name {rule.name!r}: use '<family>.<variant>'")
        if not _SLUG.match(rule.category):
            raise ValueError(f"invalid category {rule.category!r} for rule {rule.name!r}")
        if rule.name in self._rules:
            raise ValueError(f"duplicate rule name {rule.name!r}")
        self._rules[rule.name] = rule
        return rule

    @property
    def rules(self) -> tuple[Rule, ...]:
        return tuple(self._rules.values())

    def evaluate(self, request: CapturedRequest) -> list[Detection]:
        """All detections for a request, at most one per rule, in registration order.

        A rule that raises is logged by name and skipped: one buggy rule must not
        stop detection for everything else or crash the worker.
        """
        inspection = Inspection(request)
        detections: list[Detection] = []
        for rule in self._rules.values():
            try:
                matched = rule.match(inspection)
            except Exception:
                logger.exception("detection_rule_failed", rule=rule.name)
                continue
            if matched is not None:
                detections.append(
                    Detection(
                        rule=rule.name,
                        category=rule.category,
                        severity=rule.severity,
                        matched_excerpt=matched[:MAX_EXCERPT_CHARS],
                    )
                )
        return detections


default_registry = RuleRegistry()
