"""Canary tokens: bait secrets that are unique per world.

Every secret a world hands out (database password, JWT signing key, cloud keys...) is a
canary. Seeing one used anywhere else identifies the world, and so the attacker session,
that leaked it.

Tokens are derived, not stored: HMAC-SHA256 over the world id and the kind, keyed with a
server-side secret. The same world always gets the same value (the bait stays consistent
across requests and restarts, with nothing in Redis) while an attacker who knows the
algorithm still cannot compute another world's tokens or forge one. Registering a token
for lookup on use is a separate step (the ``canary_tokens`` table).

Values are deliberately NOT shaped like real provider credentials (no ``AKIA``, ``sk_live_``,
``ghp_``...), so secret scanners do not flag this repository or the honeypot's responses
as leaking real keys. They are long enough to be unique and unguessable.
"""

import hashlib
import hmac
from collections.abc import Mapping
from enum import StrEnum

_SEP = b"\x1f"
_ALNUM = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no look-alikes
_HEX = "0123456789abcdef"
_UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_URLSAFE = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
_SECRET_AWS = _ALNUM + "/"


class CanaryKind(StrEnum):
    DB_PASSWORD = "db_password"  # noqa: S105
    REDIS_PASSWORD = "redis_password"  # noqa: S105
    JWT_SECRET = "jwt_secret"  # noqa: S105
    SMTP_PASSWORD = "smtp_password"  # noqa: S105
    AWS_ACCESS_KEY_ID = "aws_access_key_id"
    AWS_SECRET_ACCESS_KEY = "aws_secret_access_key"  # noqa: S105
    GIT_TOKEN = "git_token"  # noqa: S105


_SHAPES: Mapping[CanaryKind, tuple[str, str, int]] = {
    CanaryKind.DB_PASSWORD: ("", _ALNUM, 24),
    CanaryKind.REDIS_PASSWORD: ("", _HEX, 32),
    CanaryKind.JWT_SECRET: ("", _URLSAFE, 43),
    CanaryKind.SMTP_PASSWORD: ("", _ALNUM, 20),
    CanaryKind.AWS_ACCESS_KEY_ID: ("SN", _UPPER, 18),
    CanaryKind.AWS_SECRET_ACCESS_KEY: ("", _SECRET_AWS, 40),
    CanaryKind.GIT_TOKEN: ("", _HEX, 40),
}


def _stream(key: bytes, world_id: str, kind: CanaryKind, length: int) -> bytes:
    """``length`` pseudo-random bytes bound to (key, world, kind); HMAC in counter mode."""
    out = b""
    counter = 0
    while len(out) < length:
        message = _SEP.join((world_id.encode(), kind.value.encode(), str(counter).encode()))
        out += hmac.new(key, message, hashlib.sha256).digest()
        counter += 1
    return out[:length]


def canary_token(world_id: str, kind: CanaryKind, key: bytes) -> str:
    """The canary of ``kind`` for ``world_id``; stable for a given key."""
    if not key:
        raise ValueError("canary key must not be empty")
    prefix, alphabet, length = _SHAPES[kind]
    raw = _stream(key, world_id, kind, length)
    return prefix + "".join(alphabet[b % len(alphabet)] for b in raw)


def canaries_for(world_id: str, key: bytes) -> dict[CanaryKind, str]:
    """Every canary of a world, e.g. to register them or fill the bait templates."""
    return {kind: canary_token(world_id, kind, key) for kind in CanaryKind}
