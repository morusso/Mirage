from ipaddress import IPv4Network, ip_address, ip_network

import pytest

from app.capture.client_ip import resolve_client_ip

TRUSTED = [ip_network("10.0.0.0/8"), ip_network("fd00::/8")]


def _resolve(peer: str, header: str | None) -> str:
    return str(resolve_client_ip(ip_address(peer), header, TRUSTED))


def test_header_is_ignored_when_peer_is_not_a_trusted_proxy() -> None:
    assert _resolve("198.51.100.9", "1.2.3.4") == "198.51.100.9"


def test_without_header_peer_is_used() -> None:
    assert _resolve("10.0.0.2", None) == "10.0.0.2"
    assert _resolve("10.0.0.2", "") == "10.0.0.2"


def test_trusted_proxy_forwards_client_address() -> None:
    assert _resolve("10.0.0.2", "203.0.113.5") == "203.0.113.5"


def test_client_supplied_entries_on_the_left_are_not_trusted() -> None:
    # The client sent "6.6.6.6"; my proxy appended the address it really saw.
    assert _resolve("10.0.0.2", "6.6.6.6, 203.0.113.5") == "203.0.113.5"


def test_chain_of_trusted_proxies_is_skipped() -> None:
    assert _resolve("10.0.0.2", "203.0.113.5, 10.0.0.7") == "203.0.113.5"


def test_all_hops_trusted_returns_leftmost() -> None:
    assert _resolve("10.0.0.2", "10.0.0.8, 10.0.0.7") == "10.0.0.8"


def test_garbage_entry_stops_the_walk() -> None:
    assert _resolve("10.0.0.2", "6.6.6.6, not-an-ip, 10.0.0.7") == "10.0.0.7"


def test_ipv6_clients_and_proxies() -> None:
    assert _resolve("fd00::2", "2001:db8::5") == "2001:db8::5"
    assert _resolve("10.0.0.2", "2001:db8::5") == "2001:db8::5"


def test_ipv4_proxy_network_does_not_match_ipv6_peer() -> None:
    assert _resolve("2001:db8::1", "1.2.3.4") == "2001:db8::1"


@pytest.mark.parametrize("trusted", [[], [ip_network("192.0.2.0/24")]])
def test_no_matching_trusted_network_means_peer_wins(trusted: list[IPv4Network]) -> None:
    result = resolve_client_ip(ip_address("10.0.0.2"), "1.2.3.4", trusted)

    assert str(result) == "10.0.0.2"
