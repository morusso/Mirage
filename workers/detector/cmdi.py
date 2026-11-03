"""OS command injection rules.

An attacker who reaches a shell chains a command onto the intended one (``; id``,
``| whoami``, ``$(id)``), spawns a shell, downloads and runs a payload, or opens a
reverse shell. Words like "cat", "id" or "curl" are ordinary text, so a command only
counts after a shell separator, and the ambiguous ones also need an argument (or the
end of the input) behind them: ``; cat /etc/passwd`` fires, ``cat food`` and
``&id=5`` do not. Text is the normalized form from ``Inspection``, so ``%0a`` is a
newline and ``%3b`` a semicolon.

All patterns are linear: no nested quantifiers, bounded gaps.
"""

import re
from typing import ClassVar

from workers.detector.rules import RegexRule, Rule, Severity

_FLAGS = re.IGNORECASE
_SEP = r"(?:;|\|\|?|&&|&\s|`|\$\(|\n)\s{0,20}"
# Almost never innocent after a separator.
_STRONG = (
    r"whoami|uname|ifconfig|printenv|nslookup|certutil|bitsadmin|powershell|"
    r"netstat|systeminfo|ipconfig|tasklist"
)
_WEAK = (
    r"cat|ls|id|pwd|ps|env|echo|sleep|ping|rm|cp|mv|nc|ncat|netcat|curl|wget|bash|sh|zsh|"
    r"dash|python[23]?|perl|php|ruby|chmod|chown|base64|telnet|sudo|dir|type|net|find|dig"
)
_ARG = r"(?:\s{1,5}(?:[-/~$.'\"<>|\d]|(?:https?|ftp)://)|\s{0,5}(?:$|[;&|`)]))"


def _compile(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p, _FLAGS) for p in patterns)


class ShellChain(RegexRule):
    """A command appended after a separator or inside ``$( )`` / backticks."""

    name = "cmdi.shell_chain"
    category = "cmdi"
    severity = Severity.HIGH
    patterns: ClassVar = _compile(
        rf"{_SEP}(?:{_STRONG})\b(?!\s{{0,5}}=)",
        rf"{_SEP}(?:{_WEAK})\b{_ARG}",
    )


class ShellPath(RegexRule):
    """Naming a shell or interpreter outright: ``/bin/sh -c``, ``cmd.exe /c``."""

    name = "cmdi.shell_path"
    category = "cmdi"
    severity = Severity.HIGH
    patterns: ClassVar = _compile(
        r"/(?:usr/)?s?bin/(?:(?:ba|da|z|k|c|tc|a)?sh|busybox|nc|ncat|netcat|python[23]?|"
        r"perl|php|ruby|wget|curl)\b",
        r"\b(?:cmd|command)\.exe\b",
        r"\bcmd\s{1,5}/[ck]\b",
        r"\bpowershell(?:\.exe)?\s{1,5}-(?:e|ec|enc|encodedcommand|nop|noprofile|c|command|"
        r"w|windowstyle|ep|executionpolicy)\b",
    )


class IfsEvasion(RegexRule):
    """``cat${IFS}/etc/passwd``: the shell's field separator stands in for a space."""

    name = "cmdi.ifs_evasion"
    category = "cmdi"
    severity = Severity.MEDIUM
    patterns: ClassVar = _compile(r"\$\{?IFS\b")


class DownloadExecute(RegexRule):
    """Fetching a payload and making it run."""

    name = "cmdi.download_exec"
    category = "cmdi"
    severity = Severity.CRITICAL
    patterns: ClassVar = _compile(
        r"\b(?:wget|curl)\s{1,5}(?:-\S{1,20}\s{1,5}){0,5}(?:https?|ftp)://",
        r"\b(?:wget|curl)\b[^|;&]{0,150}\|\s{0,5}(?:sudo\s{1,5})?(?:ba|da|z)?sh\b",
        r"\bcertutil(?:\.exe)?\b[^;|&]{0,50}-(?:urlcache|decode)",
        r"\bbitsadmin\b[^;|&]{0,30}/transfer",
        r"\btftp\b[^;|&]{0,30}\b(?:get|put)\b",
        r"\bchmod\s{1,5}(?:(?:[ugoa]{0,3}\+)?[rwx]{1,3}|[0-7]{3,4})\s{1,5}[/.~]",
        r"\binvoke-(?:webrequest|expression)\b",
        r"\bdownload(?:string|file)\s{0,5}\(",
        r"\bnew-object\s{1,5}(?:system\.)?net\.webclient\b",
    )


class ReverseShell(RegexRule):
    """Connecting back to the attacker with a shell attached."""

    name = "cmdi.reverse_shell"
    category = "cmdi"
    severity = Severity.CRITICAL
    patterns: ClassVar = _compile(
        r"/dev/(?:tcp|udp)/",
        r"\b(?:nc|ncat|netcat)\s{1,5}[^;|&]{0,40}-[a-z]*[ec]\b",
        r"\bbash\s{1,5}-i\b",
        r"\bmkfifo\b",
        r"\bfsockopen\s{0,5}\(",
        r"\bpython[23]?\s{1,5}-c\s",
        r"\bsocket\s{0,5}\.\s{0,5}socket\s{0,5}\([^)]{0,60}\)[^;]{0,100}\b(?:connect|dup2)\b",
    )


class OutOfBandCallback(RegexRule):
    """Hostnames of the public callback services used to confirm blind injection."""

    name = "cmdi.oob_callback"
    category = "cmdi"
    severity = Severity.HIGH
    patterns: ClassVar = _compile(
        r"\b(?:[\w-]{1,63}\.){1,4}(?:oast\.(?:pro|live|site|online|fun|me)|oastify\.com|"
        r"interact\.sh|burpcollaborator\.net|dnslog\.(?:cn|link)|ceye\.io|requestbin\.net|"
        r"pipedream\.net|canarytokens\.com)\b"
    )


RULES: tuple[Rule, ...] = (
    ShellChain(),
    ShellPath(),
    IfsEvasion(),
    DownloadExecute(),
    ReverseShell(),
    OutOfBandCallback(),
)
