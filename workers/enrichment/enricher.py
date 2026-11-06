"""Everything known about an IP address, gathered in one place.

Each source is optional (no database file or API key configured means that field stays
empty) and every lookup is failure-tolerant, so ``enrich`` never raises for a bad
address or an unreachable service: a session without a country is better than a stalled
pipeline.
"""

import asyncio
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from typing import Protocol

from workers.enrichment.abuseipdb import Reputation
from workers.enrichment.asn import AsnLookup, subnet_of
from workers.enrichment.geo import GeoIPLookup


class _ReverseDns(Protocol):
    async def lookup(self, ip: IPv4Address | IPv6Address) -> str | None: ...


class _Reputation(Protocol):
    async def lookup(self, ip: IPv4Address | IPv6Address) -> Reputation | None: ...


@dataclass(frozen=True, slots=True)
class Enrichment:
    subnet: str
    asn: int | None = None
    country: str | None = None
    city: str | None = None
    reverse_dns: str | None = None
    abuse_score: int | None = None


class Enricher:
    def __init__(
        self,
        *,
        geo: GeoIPLookup | None = None,
        asn: AsnLookup | None = None,
        rdns: _ReverseDns | None = None,
        reputation: _Reputation | None = None,
    ) -> None:
        self._geo = geo
        self._asn = asn
        self._rdns = rdns
        self._reputation = reputation

    async def enrich(self, ip: IPv4Address | IPv6Address) -> Enrichment:
        geo = self._geo.lookup(ip) if self._geo else None
        asn = self._asn.lookup(ip) if self._asn else None
        # Network sources only for public addresses: nothing useful comes back for the
        # rest, and internal ranges should not be sent to third parties.
        rdns, reputation = (None, None)
        if ip.is_global:
            rdns, reputation = await asyncio.gather(
                self._rdns.lookup(ip) if self._rdns else _none(),
                self._reputation.lookup(ip) if self._reputation else _none(),
            )
        return Enrichment(
            subnet=str(subnet_of(ip)),
            asn=asn.asn if asn else None,
            country=geo.country if geo else None,
            city=geo.city if geo else None,
            reverse_dns=rdns,
            abuse_score=reputation.abuse_score if reputation else None,
        )


async def _none() -> None:
    return None
