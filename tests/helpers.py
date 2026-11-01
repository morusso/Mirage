import base64
import json
from typing import Any


def decode_jwt_part(part: str) -> dict[str, Any]:
    """Decode one base64url JSON segment of a JWT (no verification)."""
    result: dict[str, Any] = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    return result
