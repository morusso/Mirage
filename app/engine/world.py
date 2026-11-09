"""WorldState: one attacker's world, seen through the request they just sent.

The base world comes from the seed (``world_data``), the attacker's changes from the
delta store (``world_delta``). ``snapshot_for`` merges the two and cuts out only what
the request is about, so the model prompt stays small and the model answers from facts
instead of inventing them: if the attacker created user 1042 a minute ago, a GET for it
must show that user, and a GET for user 7777 must show that there is none.

(Not in ``world_state.py``: that module holds the seed, which ``world_data`` imports.)
"""

import asyncio
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl

from pydantic import BaseModel

from app.engine.signature import normalize_path
from app.engine.world_data import (
    PRODUCT_COUNT,
    USER_COUNT,
    base_product,
    base_user,
)
from app.engine.world_delta import DELETED, DeltaStore
from domain.captured_request import CapturedRequest

# Bounds on what an attacker can make us look up or put into a prompt.
MAX_REFERENCED_IDS = 10
SAMPLE_SIZE = 3
MAX_ID_DIGITS = 9


@dataclass(frozen=True, slots=True)
class Kind:
    name: str  # plural, as it appears in URLs and in the delta store
    singular: str  # as it appears in parameter names: user_id, userId
    base_count: int
    base: Callable[[str, int], BaseModel | None]


KINDS = (
    Kind("users", "user", USER_COUNT, base_user),
    Kind("products", "product", PRODUCT_COUNT, base_product),
)


def _to_id(value: object) -> int | None:
    """A positive id from a JSON number or a string of ASCII digits; anything else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        if not (value.isascii() and value.isdecimal() and len(value) <= MAX_ID_DIGITS):
            return None
        value = int(value)
    if isinstance(value, int) and 0 < value < 10**MAX_ID_DIGITS:
        return value
    return None


def _id_fields(kind: Kind, path_kinds: set[str]) -> set[str]:
    fields = {f"{kind.singular}_id", f"{kind.singular}Id"}
    if kind.name in path_kinds:
        fields.add("id")  # /users?id=5 is about a user, a bare id elsewhere is ambiguous
    return fields


def _body_objects(request: CapturedRequest) -> list[dict[str, Any]]:
    """The JSON body's top-level object and the objects in its top-level lists."""
    try:
        body = json.loads(request.body_excerpt) if request.body_excerpt else None
    except ValueError:  # includes a body cut off at the excerpt limit
        return []
    if not isinstance(body, dict):
        return []
    found = [body]
    for value in body.values():
        if isinstance(value, list):
            found.extend(item for item in value if isinstance(item, dict))
    return found


def path_kinds(request: CapturedRequest) -> set[str]:
    segments = normalize_path(request.path).split("/")
    return {k.name for k in KINDS if k.name in segments}


def referenced_ids(request: CapturedRequest) -> dict[str, list[int]]:
    """Object ids the request names, per kind, in order of appearance (capped)."""
    segments = normalize_path(request.path).split("/")
    mentioned = path_kinds(request)
    query = parse_qsl(request.query, keep_blank_values=True, max_num_fields=100)
    objects = _body_objects(request)
    result: dict[str, list[int]] = {}
    for kind in KINDS:
        fields = _id_fields(kind, mentioned)
        candidates: list[object] = [
            segments[i + 1] for i, segment in enumerate(segments[:-1]) if segment == kind.name
        ]
        candidates += [v for k, v in query if k in fields]
        candidates += [o[f] for o in objects for f in fields if f in o]
        ids = (i for c in candidates if (i := _to_id(c)) is not None)
        unique = list(dict.fromkeys(ids))[:MAX_REFERENCED_IDS]
        if unique:
            result[kind.name] = unique
    return result


class WorldState:
    def __init__(self, delta: DeltaStore) -> None:
        self.delta = delta

    async def snapshot_for(self, world_id: str, request: CapturedRequest) -> dict[str, Any]:
        """What the world holds that is relevant to this request.

        Per kind: ``requested`` maps each id the request names to its object, or to
        null if it does not exist (never created, or deleted). A kind named in the
        path also gets ``total`` and a ``sample`` of existing objects, which is what a
        list endpoint needs. Raises ``WorldStateUnavailable`` if Redis is down.
        """
        ids = referenced_ids(request)
        mentioned = path_kinds(request)
        snapshot: dict[str, Any] = {}
        for kind in KINDS:
            if kind.name not in ids and kind.name not in mentioned:
                continue
            part: dict[str, Any] = {}
            if kind.name in ids:
                part["requested"] = await self._requested(world_id, kind, ids[kind.name])
            if kind.name in mentioned:
                part.update(await self._overview(world_id, kind))
            snapshot[kind.name] = part
        return snapshot

    async def _object(self, world_id: str, kind: Kind, object_id: int) -> dict[str, Any] | None:
        entry = await self.delta.get(world_id, kind.name, object_id)
        return self._resolve(world_id, kind, object_id, entry)

    @staticmethod
    def _resolve(
        world_id: str, kind: Kind, object_id: int, entry: dict[str, Any] | Any | None
    ) -> dict[str, Any] | None:
        if entry is DELETED:
            return None
        if entry is not None:
            return dict(entry)
        base = kind.base(world_id, object_id)
        return base.model_dump() if base is not None else None

    async def _requested(
        self, world_id: str, kind: Kind, ids: list[int]
    ) -> dict[str, dict[str, Any] | None]:
        objects = await asyncio.gather(*(self._object(world_id, kind, i) for i in ids))
        return {str(i): obj for i, obj in zip(ids, objects, strict=True)}

    async def _overview(self, world_id: str, kind: Kind) -> dict[str, Any]:
        touched = await self.delta.all(world_id, kind.name)
        base_ids = [i for i in range(1, kind.base_count + 1) if touched.get(i) is not DELETED]
        created = sorted(
            i for i, entry in touched.items() if i > kind.base_count and entry is not DELETED
        )
        existing = base_ids + created
        sample = [self._resolve(world_id, kind, i, touched.get(i)) for i in existing[:SAMPLE_SIZE]]
        return {"total": len(existing), "sample": sample}
