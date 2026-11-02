from collections.abc import Iterator
from ipaddress import ip_address
from pathlib import Path

import maxminddb
import pytest

from app.config import Settings
from workers.enrichment.geo import GeoIPLookup, GeoResult

TEST_DB = Path(__file__).parent.parent / "data" / "GeoIP2-City-Test.mmdb"


@pytest.fixture
def geo() -> Iterator[GeoIPLookup]:
    with GeoIPLookup(TEST_DB) as lookup:
        yield lookup


@pytest.mark.parametrize(
    ("ip", "expected"),
    [
        ("81.2.69.142", GeoResult(country="GB", city="London")),
        ("216.160.83.56", GeoResult(country="US", city="Milton")),
        ("89.160.20.112", GeoResult(country="SE", city="Linköping")),  # non-ASCII name
        ("2a02:ea00::1", GeoResult(country="CH", city=None)),  # IPv6, country only
    ],
)
def test_known_addresses(geo: GeoIPLookup, ip: str, expected: GeoResult) -> None:
    assert geo.lookup(ip_address(ip)) == expected


@pytest.mark.parametrize("ip", ["10.0.0.1", "192.168.1.1", "203.0.113.7", "::1"])
def test_unknown_and_private_addresses_give_empty_result(geo: GeoIPLookup, ip: str) -> None:
    assert geo.lookup(ip_address(ip)) == GeoResult(country=None, city=None)


def test_missing_database_fails_at_startup(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        GeoIPLookup(tmp_path / "nope.mmdb")


def test_corrupt_database_fails_at_startup(tmp_path: Path) -> None:
    broken = tmp_path / "broken.mmdb"
    broken.write_bytes(b"not a database")

    with pytest.raises(maxminddb.InvalidDatabaseError):
        GeoIPLookup(broken)


def test_geoip_path_is_optional_in_settings() -> None:
    assert Settings().geoip_city_db is None
    assert Settings(geoip_city_db=TEST_DB).geoip_city_db == TEST_DB
