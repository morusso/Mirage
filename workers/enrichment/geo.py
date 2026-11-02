from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from types import TracebackType
from typing import Any, Self

import maxminddb


@dataclass(frozen=True, slots=True)
class GeoResult:
    country: str | None = None  # ISO 3166-1 alpha-2, e.g. "DE"
    city: str | None = None  # English name


class GeoIPLookup:
    """Country and city of an IP address from a MaxMind GeoLite2-City database.

    The database is memory-mapped and a lookup takes microseconds, so calling it
    straight from async code does not block the event loop in any way that matters.
    Addresses that are not in the database (private ranges, documentation ranges,
    unallocated space) give an empty result, never an error.
    """

    def __init__(self, database: Path) -> None:
        # Fails loudly on a missing or corrupt file: a worker that silently enriches
        # nothing is worse than one that refuses to start.
        self._reader = maxminddb.open_database(database)

    def lookup(self, ip: IPv4Address | IPv6Address) -> GeoResult:
        record: Any = self._reader.get(str(ip))
        if not isinstance(record, dict):
            return GeoResult()
        return GeoResult(
            country=_text(record, "country", "iso_code"),
            city=_text(record, "city", "names", "en"),
        )

    def close(self) -> None:
        self._reader.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


def _text(record: dict[str, Any], *path: str) -> str | None:
    """Walk nested dicts; None if any step is missing (city is often absent)."""
    node: Any = record
    for key in path:
        if not isinstance(node, dict) or key not in node:
            return None
        node = node[key]
    return node if isinstance(node, str) and node else None
