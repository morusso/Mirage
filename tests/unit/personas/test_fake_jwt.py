import base64
import hashlib
import hmac

from app.personas.fake_jwt import FAKE_SECRET, issue_token
from tests.helpers import decode_jwt_part


def test_token_is_well_formed_hs256_jwt() -> None:
    token = issue_token({"sub": "1"}, ttl_s=60, now=1_700_000_000)

    header, payload, signature = token.split(".")
    assert decode_jwt_part(header) == {"alg": "HS256", "typ": "JWT"}
    assert decode_jwt_part(payload) == {"sub": "1", "iat": 1_700_000_000, "exp": 1_700_000_060}
    expected = hmac.new(FAKE_SECRET, f"{header}.{payload}".encode(), hashlib.sha256).digest()
    assert signature == base64.urlsafe_b64encode(expected).rstrip(b"=").decode()
    assert "=" not in token


def test_token_is_deterministic_for_same_time() -> None:
    assert issue_token({"a": 1}, now=5) == issue_token({"a": 1}, now=5)
