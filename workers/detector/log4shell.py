"""Log4Shell (CVE-2021-44228) rules.

A vulnerable Log4j expands ``${jndi:ldap://host/x}`` found in anything it logs, so
attackers put it in every header they can: User-Agent, X-Api-Version, cookies. They
hide it from filters with lookups that resolve to the letters they need:
``${${lower:j}ndi:...}``, ``${${::-j}${::-n}${::-d}${::-i}:...}``,
``${${env:X:-j}ndi:...}``. ``deobfuscate`` resolves those the way Log4j does, so the
rules see the final ``${jndi:``.

Ordinary placeholders (``${price}``, ``${user.name}``) are not lookups of a Log4j
prefix and stay quiet. Patterns are linear: bounded gaps, a bounded number of
deobfuscation rounds over text already capped by ``Inspection``.
"""

import re
from abc import abstractmethod

from workers.detector.rules import Inspection, Location, Rule, Severity

MAX_ROUNDS = 6  # nesting depth resolved; deeper is treated as the attacker's problem
MAX_OPENINGS = 20  # ``${`` positions tried when looking for the original payload
MAX_PAYLOAD_CHARS = 200  # reach of one lookup, braces balanced or not

_LOOKUP = re.compile(
    r"\$\{(?:(?:lower|upper):([^${}]{0,20})|[^${}]{0,20}:-([^${}]{0,20}))\}",
    re.IGNORECASE,
)
_JNDI = re.compile(r"\$\{\s{0,5}jndi\s{0,5}:[^}]{0,150}\}?", re.IGNORECASE)
_LOOKUP_PROBE = re.compile(
    r"\$\{\s{0,5}(?:env|sys|java|ctx|main|bundle|docker|k8s|spring|web|log4j)\s{0,5}:"
    r"\s{0,5}[\w.:-]{1,60}",
    re.IGNORECASE,
)


def _resolve(match: re.Match[str]) -> str:
    return match.group(1) if match.group(1) is not None else match.group(2)


def deobfuscate(text: str) -> str:
    """Resolve ``${lower:..}``, ``${upper:..}`` and ``${..:-default}`` until stable."""
    for _ in range(MAX_ROUNDS):
        resolved = _LOOKUP.sub(_resolve, text)
        if resolved == text:
            break
        text = resolved
    return text


def _lookup_at(text: str, start: int) -> str:
    """The ``${...}`` opening at ``start``, up to its closing brace (or the length cap)."""
    depth = 0
    window = text[start : start + MAX_PAYLOAD_CHARS]
    for index, char in enumerate(window):
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return window[: index + 1]
    return window


def original_payload(text: str) -> str | None:
    """The lookup as the sender wrote it, whose deobfuscated form is a JNDI lookup."""
    start = -1
    for _ in range(MAX_OPENINGS):
        start = text.find("${", start + 1)
        if start == -1:
            return None
        lookup = _lookup_at(text, start)
        if _JNDI.match(deobfuscate(lookup)):
            return lookup
    return None


class _Log4ShellRule(Rule):
    category = "log4shell"

    def match(self, inspection: Inspection) -> str | None:
        for text in inspection.texts(tuple(Location)):
            if "${" not in text:
                continue  # every form needs the opening, and most requests lack it
            if (found := self.match_text(text)) is not None:
                return found
        return None

    @abstractmethod
    def match_text(self, text: str) -> str | None:
        """The offending text if ``text`` matches, otherwise None."""


class JndiLookup(_Log4ShellRule):
    """``${jndi:...}``, written plainly or hidden behind lookups."""

    name = "log4shell.jndi_lookup"
    severity = Severity.CRITICAL

    def match_text(self, text: str) -> str | None:
        found = _JNDI.search(deobfuscate(text))
        return found.group(0) if found else None


class JndiObfuscated(_Log4ShellRule):
    """A JNDI lookup that only appears after deobfuscation: the sender is dodging filters.

    The excerpt is the payload as sent, so the analyst sees which evasion was used;
    ``JndiLookup`` reports the resolved form, which is stable for grouping.
    """

    name = "log4shell.jndi_obfuscated"
    severity = Severity.CRITICAL

    def match_text(self, text: str) -> str | None:
        if _JNDI.search(text):
            return None
        return original_payload(text)


class LookupProbe(_Log4ShellRule):
    """Other lookups used to leak data (``${env:AWS_SECRET_ACCESS_KEY}``) or test for Log4j."""

    name = "log4shell.lookup_probe"
    severity = Severity.MEDIUM

    def match_text(self, text: str) -> str | None:
        found = _LOOKUP_PROBE.search(text)
        return found.group(0) if found else None


RULES: tuple[Rule, ...] = (
    JndiLookup(),
    JndiObfuscated(),
    LookupProbe(),
)
