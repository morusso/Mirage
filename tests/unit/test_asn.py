from collections.abc import Iterator
from ipaddress import ip_address
from pathlib import Path

import maxminddb
import pytest

from app.config import Settings
from domain.network import subnet_of
from workers.enrichment.asn import AsnLookup, AsnResult

TEST_DB = Path(__file__).parent.parent / "data" / "GeoLite2-ASN-Test.mmdb"


@pytest.fixture
def asn() -> Iterator[AsnLookup]:
    with AsnLookup(TEST_DB) as lookup:
        yield lookup


@pytest.mark.parametrize(
    ("ip", "expected"),
    [
        ("1.0.0.1", AsnResult(asn=15169, organization="Google Inc.")),
        ("89.160.20.112", AsnResult(asn=29518, organization="Bredband2 AB")),
        ("2600:6000::1", AsnResult(asn=237, organization="Merit Network Inc.")),  # IPv6
        ("216.160.83.56", AsnResult(asn=209, organization=None)),  # record without a name
    ],
)
def test_known_addresses(asn: AsnLookup, ip: str, expected: AsnResult) -> None:
    assert asn.lookup(ip_address(ip)) == expected


@pytest.mark.parametrize("ip", ["10.0.0.1", "203.0.113.7", "2a02:ea00::1", "::1"])
def test_unknown_addresses_give_empty_result(asn: AsnLookup, ip: str) -> None:
    assert asn.lookup(ip_address(ip)) == AsnResult()


def test_missing_database_fails_at_startup(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        AsnLookup(tmp_path / "nope.mmdb")


def test_corrupt_database_fails_at_startup(tmp_path: Path) -> None:
    broken = tmp_path / "broken.mmdb"
    broken.write_bytes(b"not a database")

    with pytest.raises(maxminddb.InvalidDatabaseError):
        AsnLookup(broken)


@pytest.mark.parametrize(
    ("ip", "expected"),
    [
        ("203.0.113.77", "203.0.113.0/24"),
        ("203.0.113.0", "203.0.113.0/24"),
        ("203.0.113.255", "203.0.113.0/24"),
        ("2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:db8:1:2::/64"),
        ("::1", "::/64"),
        ("::ffff:203.0.113.77", "203.0.113.0/24"),  # IPv4-mapped counts as IPv4
    ],
)
def test_subnet_of(ip: str, expected: str) -> None:
    assert str(subnet_of(ip_address(ip))) == expected


def test_addresses_in_one_subnet_share_a_bucket() -> None:
    assert subnet_of(ip_address("198.51.100.1")) == subnet_of(ip_address("198.51.100.200"))
    assert subnet_of(ip_address("198.51.100.1")) != subnet_of(ip_address("198.51.101.1"))


def test_asn_path_is_optional_in_settings() -> None:
    assert Settings().geoip_asn_db is None
    assert Settings(geoip_asn_db=TEST_DB).geoip_asn_db == TEST_DB
