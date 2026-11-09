"""StateUpdate: how a model may ask for a change to the world.

The model never writes to Redis. It can only propose updates, which are parsed and
validated here and then applied by ``WorldState.apply``. Anything malformed is dropped
one update at a time, so a good update is not lost because its neighbour was junk.
"""

from typing import Any, Literal

import structlog
from pydantic import BaseModel, ConfigDict, Field, ValidationError

logger = structlog.get_logger()

MAX_UPDATES = 10
MAX_FIELDS = 20
MAX_TEXT_CHARS = 500

Scalar = str | int | float | bool | None


class StateUpdate(BaseModel):
    """One change: create, update or delete an object of a known kind."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    op: Literal["create", "update", "delete"]
    kind: Literal["users", "products"]
    # create: optional, the world assigns the next free id when it is missing.
    # update and delete: the object to change.
    id: int | None = Field(default=None, gt=0, lt=10**9)
    # create: fields the model chose (the rest is generated); update: fields to change.
    fields: dict[str, Scalar] = Field(default_factory=dict, max_length=MAX_FIELDS)

    def model_post_init(self, __context: Any) -> None:
        if self.op != "create" and self.id is None:
            raise ValueError(f"{self.op} needs an id")
        if self.op == "delete" and self.fields:
            raise ValueError("delete takes no fields")
        for key, value in self.fields.items():
            if len(key) > 64 or (isinstance(value, str) and len(value) > MAX_TEXT_CHARS):
                raise ValueError("field too large")


def parse_updates(raw: object) -> list[StateUpdate]:
    """Valid updates from untrusted model output; invalid ones and the excess are dropped."""
    if not isinstance(raw, list):
        return []
    updates: list[StateUpdate] = []
    for item in raw[:MAX_UPDATES]:
        try:
            updates.append(StateUpdate.model_validate(item))
        except ValidationError:
            # No details: they would quote attacker-influenced model output.
            logger.warning("state_update_invalid")
    return updates
