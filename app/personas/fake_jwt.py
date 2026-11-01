"""Fake but well-formed HS256 JWTs for the bait API.

The signing key is a made-up constant: tokens look real to tooling that decodes
them, but grant nothing anywhere.
"""

import base64
import hashlib
import hmac
import json
import time
from typing import Any

FAKE_SECRET = b"mirage-bait-signing-key"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, separators=(",", ":")).encode()


def issue_token(claims: dict[str, Any], *, ttl_s: int = 3600, now: float | None = None) -> str:
    issued_at = int(time.time() if now is None else now)
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {**claims, "iat": issued_at, "exp": issued_at + ttl_s}
    signing_input = f"{_b64url(_json(header))}.{_b64url(_json(payload))}"
    signature = hmac.new(FAKE_SECRET, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url(signature)}"
