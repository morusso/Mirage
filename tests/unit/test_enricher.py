from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path

import pytest

from workers.enrichment.abuseipdb import Reputation
from workers.enrichment.asn import AsnLookup
from workers.enrichment.enricher import Enricher
from workers.enrichment.geo import GeoIPLookup

DATA = Path(__file__).parent.parent / "data"


class FakeRdns:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def lookup(self, ip: IPv4Address | IPv6Address) -> str | None:
        self.calls.append(str(ip))
        return "scanner.example.net"


class FakeReputation:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def lookup(self, ip: IPv4Address | IPv6Address) -> Reputation | None:
        self.calls.append(str(ip))
        return Reputation(
            abuse_score=87, total_reports=5, last_reported_at=None, usage_type=None, isp=None
        )


@pytest.fixture
def enricher() -> Enricher:
    return Enricher(
        geo=GeoIPLookup(DATA / "GeoIP2-City-Test.mmdb"),
        asn=AsnLookup(DATA / "GeoLite2-ASN-Test.mmdb"),
        rdns=FakeRdns(),
        reputation=FakeReputation(),
    )


async def test_public_address_gets_every_field(enricher: Enricher) -> None:
    result = await enricher.enrich(ip_address("89.160.20.112"))

    assert (result.country, result.city) == ("SE", "Linköping")
    assert result.asn == 29518
    assert result.subnet == "89.160.20.0/24"
    assert result.reverse_dns == "scanner.example.net"
    assert result.abuse_score == 87


async def test_private_address_never_reaches_network_sources() -> None:
    rdns, reputation = FakeRdns(), FakeReputation()
    enricher = Enricher(rdns=rdns, reputation=reputation)

    result = await enricher.enrich(ip_address("10.1.2.3"))

    assert rdns.calls == [] and reputation.calls == []
    assert (result.subnet, result.country, result.reverse_dns, result.abuse_score) == (
        "10.1.2.0/24",
        None,
        None,
        None,
    )


async def test_no_sources_configured_still_gives_a_subnet() -> None:
    result = await Enricher().enrich(ip_address("2001:db8::1"))

    assert result.subnet == "2001:db8::/64"
    assert result.asn is None and result.abuse_score is None
