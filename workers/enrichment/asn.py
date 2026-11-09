from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from types import TracebackType
from typing import Any, Self

import maxminddb


@dataclass(frozen=True, slots=True)
class AsnResult:
    asn: int | None = None  # autonomous system number, e.g. 15169
    organization: str | None = None  # e.g. "Google LLC"; some records have none


class AsnLookup:
    """Autonomous system of an IP address from a MaxMind GeoLite2-ASN database.

    Same contract as GeoIPLookup: memory-mapped, microsecond lookups, an empty
    result for unknown addresses, and a loud failure at startup for a bad file.
    """

    def __init__(self, database: Path) -> None:
        self._reader = maxminddb.open_database(database)

    def lookup(self, ip: IPv4Address | IPv6Address) -> AsnResult:
        record: Any = self._reader.get(str(ip))
        if not isinstance(record, dict):
            return AsnResult()
        number = record.get("autonomous_system_number")
        organization = record.get("autonomous_system_organization")
        return AsnResult(
            asn=number if isinstance(number, int) else None,
            organization=organization if isinstance(organization, str) and organization else None,
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
