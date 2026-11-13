"""Detect a model answer that repeats its own system prompt.

A prompt injection that gets through can make the model paste its instructions into
the body or a header. Nothing in the answer's schema stops that, so the engine checks
it: the answer is refused if it contains the per-call marker nonce or any long stretch
of the system message. Whitespace is normalized first, because models re-wrap text.

The window is long enough that ordinary answers (JSON error shapes, content types) do
not match by accident, and short enough to catch a quoted rule or two.
"""

import re

from app.engine.response import GeneratedResponse

WINDOW_CHARS = 48
STRIDE_CHARS = 8  # any leaked stretch of WINDOW_CHARS + STRIDE_CHARS - 1 is caught

_SPACE = re.compile(r"\s+")
_NONCE = re.compile(r"BEGIN CLIENT REQUEST (\w+)")


def _squash(text: str) -> str:
    return _SPACE.sub(" ", text).strip().lower()


def leaks_system_prompt(system: str, response: GeneratedResponse) -> bool:
    output = _squash(
        " ".join([response.body, *response.headers.keys(), *response.headers.values()])
    )
    if not output:
        return False
    nonce = _NONCE.search(system)
    if nonce and nonce.group(1).lower() in output:
        return True
    text = _squash(system)
    return any(
        text[i : i + WINDOW_CHARS] in output
        for i in range(0, max(len(text) - WINDOW_CHARS, 0) + 1, STRIDE_CHARS)
    )
