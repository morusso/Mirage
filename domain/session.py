"""What the honeypot knows about a session at the moment a request arrives.

``SessionSignals`` is the input the router (``ModelRouter``) decides on. It is a snapshot,
not a live object: whoever builds it (the session tracker, from Redis) is responsible
for it being cheap to read, and the router never mutates it.

Every field has a defined value for a session that has just started, so the first
request of a session can be routed like any other: see ``SessionSignals.initial``.
"""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

Label = Annotated[str, StringConstraints(min_length=1, max_length=64, pattern=r"^[a-z0-9_.\-]+$")]


class SessionSignals(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    request_count: int = Field(default=1, ge=1)
    path_diversity: float = Field(default=1.0, ge=0.0, le=1.0)
    mean_interval_s: float = Field(default=0.0, ge=0.0)
    known_tool: Label | None = None
    classification: Label | None = None
    interest_score: float = Field(default=0.0, ge=0.0, le=1.0)

    @classmethod
    def initial(cls) -> "SessionSignals":
        """Signals for the first request of a session: nothing is known yet."""
        return cls()
