"""SQL injection rules.

Patterns look for SQL *structure* an honest request has no reason to contain
(UNION ... SELECT, ``OR 1=1``, ``SLEEP(5)``, ``information_schema``), not for single
words like "select" or a lone quote: a shop search for "union station" or a
customer called O'Brien must not fire anything. Everything runs on the normalized
text from ``Inspection`` (URL-decoded, NUL-free), case-insensitively, over every
location including headers (cookies and User-Agent are classic injection points).

All patterns are linear: no nested quantifiers, bounded gaps.
"""

import re
from typing import ClassVar

from workers.detector.rules import RegexRule, Rule, Severity

_FLAGS = re.IGNORECASE
# Whitespace or an inline comment, the usual way to break up keywords: UNION/**/SELECT.
_GAP = r"(?:\s|/\*[^*]{0,50}\*/)+"


def _compile(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p, _FLAGS) for p in patterns)


class UnionSelect(RegexRule):
    name = "sqli.union_select"
    category = "sqli"
    severity = Severity.HIGH
    patterns: ClassVar = _compile(rf"\bunion{_GAP}(?:all{_GAP}|distinct{_GAP})?select\b")


class Tautology(RegexRule):
    """``OR 1=1``, ``' OR 'a'='a``: a condition that is always true.

    The closing quote is optional because the application's own quote closes it.
    """

    name = "sqli.tautology"
    category = "sqli"
    severity = Severity.HIGH
    patterns: ClassVar = _compile(
        r"\b(?:or|and)\s+(['\"]?)(\w{1,20})\1\s*(?:=|like)\s*\1\2\1?(?!\w)",
        r"\b(?:or|and)\s+(\d{1,10})\s*(?:<>|!=)\s*(?!\1\b)\d{1,10}\b",
    )


class CommentTerminator(RegexRule):
    """A quote straight into a comment: ``admin'--`` cuts off the rest of the query."""

    name = "sqli.comment_terminator"
    category = "sqli"
    severity = Severity.MEDIUM
    patterns: ClassVar = _compile(r"['\"`)]\s*(?:--|/\*|;\s*--)")


class TimeBased(RegexRule):
    name = "sqli.time_based"
    category = "sqli"
    severity = Severity.HIGH
    patterns: ClassVar = _compile(
        r"\b(?:pg_)?sleep\s*\(\s*\d",
        r"\bbenchmark\s*\(\s*\d+\s*,",
        r"\bwaitfor\s+delay\s+['\"]",
        r"\bdbms_pipe\.receive_message\s*\(",
    )


class BooleanBlind(RegexRule):
    """Extracting data one bit at a time: ``AND ASCII(SUBSTRING((SELECT ...``."""

    name = "sqli.boolean_blind"
    category = "sqli"
    severity = Severity.MEDIUM
    patterns: ClassVar = _compile(
        r"\b(?:and|or)\s+\(*\s*select\b",
        r"\b(?:and|or)\s+\(*\s*(?:ascii|ord|substring|substr|mid|length|char|if)\s*\(",
        r"\bcase\s+when\b[^;]{0,80}\bthen\b",
    )


class ErrorBased(RegexRule):
    """Functions abused to leak data through error messages."""

    name = "sqli.error_based"
    category = "sqli"
    severity = Severity.HIGH
    patterns: ClassVar = _compile(
        r"\b(?:extractvalue|updatexml)\s*\(",
        r"\bexp\s*\(\s*~\s*\(",
        r"\bconvert\s*\(\s*int\s*,",
    )


class SchemaEnumeration(RegexRule):
    name = "sqli.schema_enum"
    category = "sqli"
    severity = Severity.HIGH
    patterns: ClassVar = _compile(
        r"\binformation_schema\b",
        r"\b(?:sqlite_master|sqlite_schema|pg_catalog|pg_tables|all_tables|user_tables)\b",
        r"\bsys\.(?:tables|columns|objects|databases)\b",
        r"\bmysql\.user\b",
    )


class StackedQuery(RegexRule):
    """A second statement after a terminator: ``'; DROP TABLE users--``."""

    name = "sqli.stacked_query"
    category = "sqli"
    severity = Severity.HIGH
    patterns: ClassVar = _compile(
        r";\s*(?:drop|truncate|alter)\s+(?:table|database|schema)\b",
        r";\s*(?:shutdown|exec(?:ute)?)\b",
        r";\s*insert\s+into\b",
        r";\s*update\s+\w{1,64}\s+set\b",
        r";\s*delete\s+from\b",
    )


class SystemAccess(RegexRule):
    """Reaching beyond the database: files, the OS, server internals."""

    name = "sqli.system_access"
    category = "sqli"
    severity = Severity.CRITICAL
    patterns: ClassVar = _compile(
        r"\binto\s+(?:out|dump)file\b",
        r"\bload_file\s*\(",
        r"\bxp_cmdshell\b",
        r"\butl_(?:http|inaddr)\.\w{1,32}\s*\(",
        r"@@(?:version|datadir|hostname|basedir)\b",
    )


class OrderByProbe(RegexRule):
    """``' ORDER BY 7--``: counting columns ahead of a UNION."""

    name = "sqli.order_by_probe"
    category = "sqli"
    severity = Severity.MEDIUM
    patterns: ClassVar = _compile(r"['\"`)]\s*order\s+by\s+\d{1,3}\b")


RULES: tuple[Rule, ...] = (
    UnionSelect(),
    Tautology(),
    CommentTerminator(),
    TimeBased(),
    BooleanBlind(),
    ErrorBased(),
    SchemaEnumeration(),
    StackedQuery(),
    SystemAccess(),
    OrderByProbe(),
)
