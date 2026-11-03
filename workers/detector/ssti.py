"""Server-side template injection rules.

Three stages of the same attack: a harmless arithmetic probe (``{{7*7}}``) to learn
which engine renders input, introspection of the object graph (Jinja2's
``__class__.__mro__``), and calls that execute commands (Freemarker ``Execute``,
Twig ``_self.env``, SpEL ``Runtime``). Plain placeholders like ``{{name}}`` or
``${price}`` are ordinary text and must stay quiet.

All patterns are linear: no nested quantifiers, bounded gaps.
"""

import re
from typing import ClassVar

from workers.detector.rules import RegexRule, Rule, Severity

_FLAGS = re.IGNORECASE
_ARITH = r"\d{1,6}\s*[*+\-/%]\s*\d{1,6}"
_STR_ARITH = r"['\"]\d{1,6}['\"]\s*\*\s*\d{1,6}"


def _compile(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p, _FLAGS) for p in patterns)


class ExpressionProbe(RegexRule):
    """``{{7*7}}``, ``${7*7}``, ``<%= 7*7 %>``, ``#{7*7}``, ``{{'7'*7}}``: engine fingerprinting."""

    name = "ssti.expression_probe"
    category = "ssti"
    severity = Severity.MEDIUM
    patterns: ClassVar = _compile(
        rf"\{{\{{\s*(?:{_ARITH}|{_STR_ARITH})\s*\}}\}}",
        rf"[$#]\{{\s*(?:{_ARITH})\s*\}}",
        rf"<%=?\s*(?:{_ARITH})\s*%>",
        rf"@\(\s*{_ARITH}\s*\)",
        rf"\{{%[^%]{{0,50}}\b{_ARITH}[^%]{{0,50}}%\}}",
    )


class PythonIntrospection(RegexRule):
    """Walking from a string to ``object.__subclasses__()`` to reach something dangerous."""

    name = "ssti.python_introspection"
    category = "ssti"
    severity = Severity.HIGH
    patterns: ClassVar = _compile(
        r"(?:\.|\[\s*['\"]|\|\s*attr\s*\(\s*['\"])__(?:class|mro|bases?|subclasses|globals|"
        r"builtins|import|getattribute|dict|code)__",
    )


class TemplateRce(RegexRule):
    """Template syntax that reaches a shell or the runtime."""

    name = "ssti.template_rce"
    category = "ssti"
    severity = Severity.CRITICAL
    patterns: ClassVar = _compile(
        # Jinja2 / Twig / Tornado: special objects and process calls inside {{ }} or {% %}.
        r"\{[{%][^}]{0,200}\b(?:lipsum|cycler|joiner|namespace|url_for|get_flashed_messages|"
        r"popen|subprocess|_self\.env|registerUndefinedFilterCallback)\b",
        r"\{\{\s*(?:config|self|request|settings)\b[^}]{0,100}\}\}",
        # Freemarker / Velocity
        r"freemarker\.template\.utility\.(?:Execute|ObjectConstructor)",
        r"<#assign\b[^>]{0,100}\bexec",
        r"#set\s*\(\s*\$\w{1,30}\s*=[^)]{0,100}(?:Runtime|ProcessBuilder|forName)",
        # SpEL / OGNL / Java EL
        r"\bT\s*\(\s*java\.lang\.(?:Runtime|ProcessBuilder|System)\s*\)",
        r"\bnew\s+java\.lang\.ProcessBuilder\b",
        r"\bgetRuntime\s*\(\s*\)\s*\.\s*exec\b",
        # ERB / EJS / Mako
        r"<%=?\s*(?:system|exec|`|IO\.popen|%x|File\.read|require\b)",
        r"<%\s*import\s+os\b",
    )


RULES: tuple[Rule, ...] = (
    ExpressionProbe(),
    PythonIntrospection(),
    TemplateRce(),
)
