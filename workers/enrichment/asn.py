from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_network
from pathlib import Path
from types import TracebackType
from typing import Any, Self

import maxminddb

IPV4_SUBNET_PREFIX = 24
IPV6_SUBNET_PREFIX = 64


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


def subnet_of(ip: IPv4Address | IPv6Address) -> IPv4Network | IPv6Network:
    """The /24 (IPv4) or /64 (IPv6) containing the address, used as a budget dimension.

    An IPv4-mapped IPv6 address (::ffff:203.0.113.7) is treated as the IPv4 address
    it wraps, so dual-stack listeners do not put one scanner in two different buckets.
    """
    if isinstance(ip, IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    prefix = IPV4_SUBNET_PREFIX if isinstance(ip, IPv4Address) else IPV6_SUBNET_PREFIX
    return ip_network(f"{ip}/{prefix}", strict=False)
