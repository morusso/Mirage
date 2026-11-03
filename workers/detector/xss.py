"""Cross-site scripting rules.

Like the SQL rules, these look for markup and script *structure* (``<script``, an
``onerror=`` inside a tag, ``javascript:`` in an attribute), not for single words:
a forum post that mentions JavaScript, a comparison like ``a<b`` or harmless
formatting such as ``<b>bold</b>`` must stay quiet. Text is the normalized form from
``Inspection`` (URL-decoded, NUL-free), matched case-insensitively, in every location.

All patterns are linear: no nested quantifiers, bounded gaps.
"""

import re
from typing import ClassVar

from workers.detector.rules import RegexRule, Rule, Severity

_FLAGS = re.IGNORECASE
_EVENTS = (
    r"on(?:error|load|click|dblclick|auxclick|mouse[a-z]{2,6}|pointer[a-z]{2,6}|"
    r"focus[a-z]{0,3}|blur|toggle|beforetoggle|key[a-z]{2,5}|submit|input|change|"
    r"begin|start|animation[a-z]{3,8}|transition[a-z]{3,8}|wheel|drag[a-z]{0,5}|"
    r"drop|copy|cut|paste|resize|scroll|show)"
)


def _compile(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p, _FLAGS) for p in patterns)


class ScriptTag(RegexRule):
    name = "xss.script_tag"
    category = "xss"
    severity = Severity.HIGH
    patterns: ClassVar = _compile(r"<\s*/?\s*script\b")


class EventHandler(RegexRule):
    """``<img src=x onerror=...>``, or ``" onmouseover="...`` breaking out of an attribute."""

    name = "xss.event_handler"
    category = "xss"
    severity = Severity.HIGH
    patterns: ClassVar = _compile(
        r"<\s*[a-z][a-z0-9]{0,19}\b[^<>]{0,200}?[\s/\"'`]on[a-z]{3,20}\s*=",
        rf"[\"'`][^<>\"'`]{{0,60}}?[\s/\"'`]{_EVENTS}\s*=",
    )


class JavascriptUri(RegexRule):
    """``href="javascript:..."`` or a ``javascript:`` URI that goes on to call something."""

    name = "xss.javascript_uri"
    category = "xss"
    severity = Severity.HIGH
    patterns: ClassVar = _compile(
        r"\b(?:href|src|action|formaction|data|xlink:href|background)\s*=\s*[\"'`]?\s*"
        r"(?:javascript|vbscript)\s*:",
        r"\bjavascript\s*:\s*[\w.$]{1,40}\s*[(`]",
        r"\bdata\s*:\s*text/html\b",
    )


class DangerousTag(RegexRule):
    """Tags with no business in user input: they load or run foreign content."""

    name = "xss.dangerous_tag"
    category = "xss"
    severity = Severity.MEDIUM
    patterns: ClassVar = _compile(
        r"<\s*(?:iframe|frameset|object|embed|applet|svg|math)\b",
        r"<\s*meta\b[^<>]{0,100}\bhttp-equiv\b",
        r"<\s*base\b[^<>]{0,100}\bhref\b",
    )


class DomSink(RegexRule):
    """The payload body itself: proof-of-concept calls and cookie theft."""

    name = "xss.dom_sink"
    category = "xss"
    severity = Severity.MEDIUM
    patterns: ClassVar = _compile(
        r"\b(?:alert|prompt|confirm)\s*[(`]\s*(?:\d|['\"`]|document\b|window\b|\))",
        r"\bdocument\s*\.\s*(?:cookie|domain|write(?:ln)?)\b",
        r"\beval\s*\(\s*(?:atob|unescape|String\b|['\"`])",
        r"\bString\s*\.\s*fromCharCode\s*\(",
    )


RULES: tuple[Rule, ...] = (
    ScriptTag(),
    EventHandler(),
    JavascriptUri(),
    DangerousTag(),
    DomSink(),
)
