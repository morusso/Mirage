from ipaddress import IPv4Address, IPv6Address
from typing import Self
from uuid import UUID, uuid4

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field


class CapturedRequest(BaseModel):
    """One request seen by the honeypot, published as a single stream event.

    Request-side fields are known on arrival; response-side fields stay ``None``
    until the response has been sent (see ``with_response``).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    # Unique per event so consumers can deduplicate redelivered stream entries.
    event_id: UUID = Field(default_factory=uuid4)
    ts: AwareDatetime

    # Identity
    session_id: UUID
    world_id: str
    persona: str | None = None

    # Origin
    ip: IPv4Address | IPv6Address
    port: int | None = Field(default=None, ge=0, le=65535)
    ja4: str | None = None

    # Request. Headers keep order and duplicates, which are useful fingerprints.
    method: str
    path: str
    query: str = ""
    headers: list[tuple[str, str]] = Field(default_factory=list)

    # Body: only an excerpt is kept, the hash always covers the whole body.
    body_excerpt: str = ""
    body_size: int = Field(default=0, ge=0)
    body_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    body_truncated: bool = False

    # Response side, filled after the response is sent.
    tier: int | None = Field(default=None, ge=0, le=2)
    status: int | None = Field(default=None, ge=100, le=599)
    latency_ms: int | None = Field(default=None, ge=0)
    tokens_used: int | None = Field(default=None, ge=0)

    def with_response(
        self, *, tier: int, status: int, latency_ms: int, tokens_used: int = 0
    ) -> Self:
        return self.model_copy(
            update={
                "tier": tier,
                "status": status,
                "latency_ms": latency_ms,
                "tokens_used": tokens_used,
            }
        )
