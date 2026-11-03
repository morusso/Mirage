"""Scanner tool signatures.

Mass-scanning tools announce themselves in their default ``User-Agent``: sqlmap,
nuclei, ffuf, gobuster, masscan, zgrab. Spotting them tells the router a request
is automated noise that templates can answer (``known_tool`` in ``SessionSignals``).

One rule per tool, named ``scanner.<tool>``, so the tool is the part of the rule
name after the dot. Only the ``User-Agent`` value is checked: a tool name in a
query, a body or a ``Referer`` is ordinary text. An attacker who changes the
default User-Agent is not caught here; behaviour-based classification covers that.

All patterns are linear: literals and word boundaries only.
"""

import re

from workers.detector.rules import MAX_PART_CHARS, Inspection, Rule, Severity

# Tool name -> pattern for its default User-Agent. Add a row to cover another tool.
SIGNATURES: dict[str, str] = {
    "sqlmap": r"\bsqlmap\b",
    "nuclei": r"\bnuclei\b",
    "ffuf": r"\bfuzz faster u fool\b|^ffuf/",
    "gobuster": r"\bgobuster\b",
    "masscan": r"\bmasscan\b",
    "zgrab": r"\bzgrab2?\b",
}


class ScannerSignature(Rule):
    """Fires when a ``User-Agent`` header carries the tool's default signature."""

    category = "scanner"
    severity = Severity.LOW

    def __init__(self, tool: str, pattern: str) -> None:
        self.tool = tool
        self.name = f"scanner.{tool}"
        self._pattern = re.compile(pattern, re.IGNORECASE)

    def match(self, inspection: Inspection) -> str | None:
        for header, value in inspection.request.headers:
            if header.lower() != "user-agent":
                continue
            if found := self._pattern.search(value[:MAX_PART_CHARS]):
                return found.group(0)
        return None


RULES: tuple[Rule, ...] = tuple(ScannerSignature(tool, p) for tool, p in SIGNATURES.items())
