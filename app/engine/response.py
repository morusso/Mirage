"""The response the engine hands back: schema of what a model may generate.

Model output is shaped by an attacker's request, so it is treated as untrusted input
and validated before anything is sent. Violations fall into two kinds:

- *Unsafe or malformed* output is rejected (the engine then falls back to tier 0):
  an out-of-range status, a header name that is not an HTTP token, a header value with
  control characters or non-ASCII text (response splitting, or a crash when the server
  encodes it), too many or too large headers.
- *Harmless junk* is quietly dropped: headers the server owns (framing, connection
  management, ``Server``, ``X-Powered-By``, which the persona sets) and extra fields.
  Models add these all the time and a 3 s call should not be wasted on them.
"""

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_BODY_CHARS = 64_000
MAX_HEADERS = 32
MAX_HEADER_NAME_CHARS = 64
MAX_HEADER_VALUE_CHARS = 2048

# Headers the server (or the persona) decides, never the model.
OWNED_HEADERS = frozenset(
    {
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "upgrade",
        "te",
        "trailer",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "server",
        "x-powered-by",
        "date",
    }
)
# 204 and 304 never carry a body.
BODYLESS_STATUSES = frozenset({204, 304})

_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")  # RFC 9110 field-name
_VALUE = re.compile(r"^[\x20-\x7e\t]*$")  # visible ASCII, space and tab only


class GeneratedResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    # 1xx are interim responses: sending one as the final answer breaks HTTP framing.
    status_code: int = Field(ge=200, le=599)
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = Field(default="", max_length=MAX_BODY_CHARS)
    # Changes to the fake world the model proposes. Raw and unvalidated here: the engine
    # parses them with ``parse_updates``. Never serialized, so it never reaches the cache.
    state_updates: Any = Field(default=None, exclude=True, repr=False)

    @field_validator("headers", mode="before")
    @classmethod
    def _stringify_numbers(cls, value: Any) -> Any:
        """Models write ``"Content-Length": 123``; numbers are fine, other types are not."""
        if isinstance(value, dict):
            return {
                k: str(v) if isinstance(v, int | float) and not isinstance(v, bool) else v
                for k, v in value.items()
            }
        return value

    @field_validator("headers")
    @classmethod
    def _clean_headers(cls, headers: dict[str, str]) -> dict[str, str]:
        if len(headers) > MAX_HEADERS:
            raise ValueError(f"more than {MAX_HEADERS} headers")
        clean: dict[str, str] = {}
        for name, value in headers.items():
            if len(name) > MAX_HEADER_NAME_CHARS or not _TOKEN.match(name):
                raise ValueError("invalid header name")
            if len(value) > MAX_HEADER_VALUE_CHARS or not _VALUE.match(value):
                raise ValueError("invalid header value")
            lowered = name.lower()
            if lowered in OWNED_HEADERS:
                continue
            if lowered in clean:
                raise ValueError("duplicate header name")
            clean[lowered] = value
        return clean

    @model_validator(mode="after")
    def _no_body_for_bodyless_statuses(self) -> "GeneratedResponse":
        if self.status_code in BODYLESS_STATUSES and self.body:
            self.body = ""
        return self
