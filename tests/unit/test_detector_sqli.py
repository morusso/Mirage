import time
from datetime import UTC, datetime
from ipaddress import ip_address
from uuid import uuid4

import pytest

from domain.captured_request import CapturedRequest
from workers.detector.rules import RuleRegistry
from workers.detector.sqli import RULES


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


# (query string, rule that must fire)
ATTACKS = [
    ("id=1 UNION SELECT username,password FROM users", "sqli.union_select"),
    ("id=1 union all select null,null,null", "sqli.union_select"),
    ("id=1+UNION/**/SELECT+1,2,3", "sqli.union_select"),
    ("id=1 UnIoN%0aSeLeCt 1", "sqli.union_select"),
    ("id=1 OR 1=1", "sqli.tautology"),
    ("user=' or 'a'='a", "sqli.tautology"),
    ('user=" OR "x"="x', "sqli.tautology"),
    ("id=1 and 2 != 3", "sqli.tautology"),
    ("user=admin'--", "sqli.comment_terminator"),
    ("user=admin' /*", "sqli.comment_terminator"),
    ("id=1)--", "sqli.comment_terminator"),
    ("id=1 AND SLEEP(5)", "sqli.time_based"),
    ("id=1;SELECT pg_sleep(10)", "sqli.time_based"),
    ("id=1 AND BENCHMARK(5000000,MD5(1))", "sqli.time_based"),
    ("id=1;WAITFOR DELAY '0:0:5'", "sqli.time_based"),
    ("id=1 AND (SELECT COUNT(*) FROM users)>0", "sqli.boolean_blind"),
    ("id=1 AND ASCII(SUBSTRING(version(),1,1))>50", "sqli.boolean_blind"),
    ("id=1 AND CASE WHEN (1=1) THEN 1 ELSE 0 END", "sqli.boolean_blind"),
    ("id=1 AND extractvalue(1,concat(0x7e,version()))", "sqli.error_based"),
    ("id=1 AND UPDATEXML(1,concat(0x7e,user()),1)", "sqli.error_based"),
    ("id=1 UNION SELECT table_name FROM information_schema.tables", "sqli.schema_enum"),
    ("q=x' AND 1=0 UNION SELECT name FROM sqlite_master", "sqli.schema_enum"),
    ("id=1; DROP TABLE users--", "sqli.stacked_query"),
    ("id=1; exec master..xp_cmdshell 'dir'", "sqli.stacked_query"),
    ("id=1; UPDATE users SET admin=1", "sqli.stacked_query"),
    ("id=1 UNION SELECT '<?php ?>' INTO OUTFILE '/var/www/x.php'", "sqli.system_access"),
    ("id=1 AND LOAD_FILE('/etc/passwd')", "sqli.system_access"),
    ("id=1 AND @@version LIKE '5%'", "sqli.system_access"),
    ("sort=name' ORDER BY 7--", "sqli.order_by_probe"),
]


@pytest.mark.parametrize(("query", "rule"), ATTACKS, ids=[a[0][:50] for a in ATTACKS])
def test_attack_fires_expected_rule(registry: RuleRegistry, query: str, rule: str) -> None:
    assert rule in _fired(registry, _request(query=query))


@pytest.mark.parametrize(
    "query",
    [
        "id=1%20UNION%20SELECT%201",  # percent-encoded
        "id=1%2520UNION%2520SELECT%25201",  # double-encoded
        "id=1%00%20UNION%20SELECT%201",  # NUL byte
    ],
)
def test_encoded_payloads_are_still_detected(registry: RuleRegistry, query: str) -> None:
    assert "sqli.union_select" in _fired(registry, _request(query=query))


def test_payload_in_body_path_and_headers(registry: RuleRegistry) -> None:
    payload = "1' UNION SELECT 1,2--"

    assert "sqli.union_select" in _fired(registry, _request(body=f'{{"id": "{payload}"}}'))
    assert "sqli.union_select" in _fired(registry, _request(path=f"/users/{payload}"))
    assert "sqli.union_select" in _fired(registry, _request(headers=[("Cookie", f"sid={payload}")]))
    assert "sqli.time_based" in _fired(
        registry, _request(headers=[("User-Agent", "Mozilla/5.0' AND SLEEP(5)--")])
    )


def test_detection_carries_rule_metadata_and_excerpt(registry: RuleRegistry) -> None:
    detections = registry.evaluate(_request(query="id=1 UNION SELECT 1 INTO OUTFILE '/x'"))

    by_rule = {d.rule: d for d in detections}
    assert by_rule["sqli.union_select"].matched_excerpt.lower() == "union select"
    assert by_rule["sqli.union_select"].category == "sqli"
    assert by_rule["sqli.system_access"].severity.value == "critical"


# Ordinary traffic that must stay quiet. Each looks a little like an attack.
CLEAN = [
    "q=union station",
    "q=select a size",
    "q=how to drop shipping",
    "q=black or white",
    "name=O'Brien",
    "name=D'Angelo&city=L'Aquila",
    "sort=price&order=asc",
    "q=cats and dogs",
    "q=rock -- roll",
    "q=sleep better tonight",
    "q=order by date",
    "q=version 2.0 of the app",
    "text=1 and 1 make 2",
    "q=tom and jerry; the movie",
    "email=a%2Bb%40example.com",
    "q=update settings",
    "page=2&limit=50&filter=in_stock",
]


@pytest.mark.parametrize("query", CLEAN)
def test_ordinary_queries_do_not_fire(registry: RuleRegistry, query: str) -> None:
    assert _fired(registry, _request(query=query)) == set()


def test_ordinary_requests_do_not_fire(registry: RuleRegistry) -> None:
    request = _request(
        path="/api/v1/products/42",
        body='{"title": "Rock -- Roll", "comment": "it\'s great, 5 stars"}',
        headers=[
            ("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"),
            ("Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"),
            ("Cookie", "session=abc123; theme=dark"),
        ],
    )

    assert _fired(registry, request) == set()


def test_rule_set_is_consistent() -> None:
    names = [rule.name for rule in RULES]

    assert len(names) == len(set(names))
    assert all(rule.category == "sqli" for rule in RULES)
    assert all(name.startswith("sqli.") for name in names)


@pytest.mark.parametrize(
    "body",
    [
        "union " * 1500,
        "union" + " " * 8000,
        "or " + "1" * 8000,
        "' " * 4000,
        "/*" * 4000,
        "and (" * 1600,
        "case when " * 800,
        "; update " + "a" * 8000,
        "'" + " " * 8000 + "x",
    ],
    ids=[
        "union-spam",
        "union-spaces",
        "or-digits",
        "quotes",
        "comments",
        "paren-spam",
        "case-spam",
        "update-long",
        "quote-spaces",
    ],
)
def test_adversarial_input_is_processed_quickly(registry: RuleRegistry, body: str) -> None:
    started = time.perf_counter()
    registry.evaluate(_request(body=body))

    assert time.perf_counter() - started < 0.5
