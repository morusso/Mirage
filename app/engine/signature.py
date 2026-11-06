"""Request signature: the cache key for tier 0 responses.

Two requests with the same signature get the same answer. The signature covers what
changes the answer (persona, method, normalized path, query, and the body of requests
that carry one) and ignores what does not (cache busters, header noise, IP).

Normalization stays conservative: path case and ``..`` segments are left alone because
they are attacker payload and a real server would treat them literally. Only changes
that cannot alter a server's answer are folded (duplicate and trailing slashes, query
parameter order, cache-busting parameters).
"""

import hashlib
import re
from urllib.parse import parse_qsl

from domain.captured_request import CapturedRequest

# Parameters clients add only to defeat caches; they never select content.
CACHE_BUSTERS = frozenset({"_", "ts", "t", "timestamp", "nocache", "cb", "cachebust", "rnd"})

_BODYLESS_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "DELETE"})
_SLASHES = re.compile(r"/{2,}")
_SEP = "\x1f"  # unit separator: cannot be confused with path or query characters


def normalize_path(path: str) -> str:
    path = _SLASHES.sub("/", path or "/")
    if not path.startswith("/"):
        path = "/" + path
    return path.rstrip("/") or "/"


def normalize_query(query: str) -> str:
    """Sorted ``name=value`` pairs without cache busters; blank values are kept."""
    pairs = [
        (k, v)
        for k, v in parse_qsl(query, keep_blank_values=True, max_num_fields=100)
        if k.lower() not in CACHE_BUSTERS
    ]
    return "&".join(f"{k}={v}" for k, v in sorted(pairs))


def request_signature(req: CapturedRequest, *, scope: str = "") -> str:
    """SHA-256 hex digest identifying the answer this request should get.

    ``scope`` partitions the cache, e.g. by world id when answers must stay consistent
    per attacker. Requests that carry a body include its hash: a login with different
    credentials is a different request.
    """
    method = req.method.upper()
    body = "" if method in _BODYLESS_METHODS else (req.body_sha256 or "")
    parts = [
        scope,
        req.persona or "",
        method,
        normalize_path(req.path),
        normalize_query(req.query),
        body,
    ]
    return hashlib.sha256(_SEP.join(parts).encode()).hexdigest()
