import time
from datetime import UTC, datetime
from ipaddress import ip_address
from uuid import uuid4

import pytest

from domain.captured_request import CapturedRequest
from workers.detector.rules import RuleRegistry, Severity
from workers.detector.scanners import RULES, SIGNATURES


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


@pytest.fixture(scope="module")
def registry() -> RuleRegistry:
    registry = RuleRegistry()
    for rule in RULES:
        registry.register(rule)
    return registry


def _fired(registry: RuleRegistry, request: CapturedRequest) -> set[str]:
    return {d.rule for d in registry.evaluate(request)}


def _ua(value: str) -> CapturedRequest:
    return _request(headers=[("User-Agent", value)])


# Default User-Agents as the tools send them.
ATTACKS = [
    ("sqlmap/1.7.11#stable (https://sqlmap.org)", "scanner.sqlmap"),
    ("sqlmap/1.5.2.3#dev (http://sqlmap.org)", "scanner.sqlmap"),
    ("Nuclei - Open-source project (github.com/projectdiscovery/nuclei)", "scanner.nuclei"),
    ("Fuzz Faster U Fool v2.1.0", "scanner.ffuf"),
    ("ffuf/2.0.0", "scanner.ffuf"),
    ("gobuster/3.6", "scanner.gobuster"),
    ("masscan/1.3 (https://github.com/robertdavidgraham/masscan)", "scanner.masscan"),
    ("Mozilla/5.0 zgrab/0.x", "scanner.zgrab"),
    ("Mozilla/5.0 (compatible; zgrab2)", "scanner.zgrab"),
    ("SQLMAP/1.7", "scanner.sqlmap"),  # case does not matter
]


@pytest.mark.parametrize(("agent", "rule"), ATTACKS, ids=[a[0][:40] for a in ATTACKS])
def test_default_user_agent_fires_its_tool_rule(
    registry: RuleRegistry, agent: str, rule: str
) -> None:
    assert _fired(registry, _ua(agent)) == {rule}


def test_header_name_is_case_insensitive(registry: RuleRegistry) -> None:
    request = _request(headers=[("user-agent", "gobuster/3.6")])

    assert _fired(registry, request) == {"scanner.gobuster"}


def test_agent_is_found_among_other_headers(registry: RuleRegistry) -> None:
    request = _request(
        headers=[("Host", "shop.example"), ("Accept", "*/*"), ("User-Agent", "gobuster/3.6")]
    )

    assert _fired(registry, request) == {"scanner.gobuster"}


def test_detection_carries_rule_metadata_and_excerpt(registry: RuleRegistry) -> None:
    (detection,) = registry.evaluate(_ua("sqlmap/1.7.11#stable (https://sqlmap.org)"))

    assert detection.rule == "scanner.sqlmap"
    assert detection.category == "scanner"
    assert detection.severity is Severity.LOW
    assert detection.matched_excerpt == "sqlmap"


# The tool name outside a User-Agent is just text.
@pytest.mark.parametrize(
    "request_",
    [
        _request(query="q=sqlmap tutorial"),
        _request(path="/blog/how-to-use-nuclei"),
        _request(body="I like ffuf and gobuster and masscan and zgrab"),
        _request(headers=[("Referer", "https://example.com/sqlmap")]),
        _request(headers=[("X-User-Agent", "sqlmap/1.7")]),
        _request(headers=[("Cookie", "tool=nuclei")]),
    ],
    ids=["query", "path", "body", "referer", "other-header", "cookie"],
)
def test_tool_names_outside_user_agent_do_not_fire(
    registry: RuleRegistry, request_: CapturedRequest
) -> None:
    assert _fired(registry, request_) == set()


CLEAN_AGENTS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "curl/8.4.0",
    "python-requests/2.31.0",
    "Go-http-client/1.1",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "nucleic-acid-viewer/1.0",  # \bnuclei\b needs the whole word
    "fuzzy-search/2.0",
    "",
]


@pytest.mark.parametrize("agent", CLEAN_AGENTS)
def test_ordinary_user_agents_do_not_fire(registry: RuleRegistry, agent: str) -> None:
    assert _fired(registry, _ua(agent)) == set()


def test_request_without_headers_does_not_fire(registry: RuleRegistry) -> None:
    assert _fired(registry, _request()) == set()


def test_several_user_agent_headers_are_all_checked(registry: RuleRegistry) -> None:
    request = _request(headers=[("User-Agent", "Mozilla/5.0"), ("User-Agent", "masscan/1.3")])

    assert _fired(registry, request) == {"scanner.masscan"}


def test_rule_set_is_consistent() -> None:
    names = [rule.name for rule in RULES]

    assert names == [f"scanner.{tool}" for tool in SIGNATURES]
    assert len(names) == len(set(names))
    assert all(rule.category == "scanner" for rule in RULES)


@pytest.mark.parametrize(
    "agent",
    ["a" * 100_000, "sqlmap" * 20_000, " " * 100_000, "fuzz faster u " * 7_000],
    ids=["long", "repeated-tool", "spaces", "partial-ffuf"],
)
def test_adversarial_user_agent_is_processed_quickly(registry: RuleRegistry, agent: str) -> None:
    started = time.perf_counter()
    registry.evaluate(_ua(agent))

    assert time.perf_counter() - started < 0.5
