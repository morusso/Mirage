from ipaddress import ip_address

from app.capture.fingerprint import fingerprint_v1

IP = ip_address("203.0.113.17")


def test_same_ip_and_user_agent_give_same_identity() -> None:
    assert fingerprint_v1(IP, "curl/8.5.0") == fingerprint_v1(IP, "curl/8.5.0")


def test_different_user_agent_gives_different_world() -> None:
    assert fingerprint_v1(IP, "curl/8.5.0") != fingerprint_v1(IP, "sqlmap/1.8")


def test_different_ip_gives_different_world() -> None:
    other = ip_address("203.0.113.18")

    assert fingerprint_v1(IP, "curl/8.5.0").world_id != fingerprint_v1(other, "curl/8.5.0").world_id


def test_missing_and_empty_user_agent_are_equivalent() -> None:
    assert fingerprint_v1(IP, None) == fingerprint_v1(IP, "")


def test_surrounding_whitespace_in_user_agent_is_ignored() -> None:
    assert fingerprint_v1(IP, "  curl/8.5.0 ") == fingerprint_v1(IP, "curl/8.5.0")


def test_world_id_format_and_session_derived_from_it() -> None:
    fp = fingerprint_v1(IP, "curl/8.5.0")

    assert fp.world_id.startswith("w_")
    assert len(fp.world_id) == 18
    assert fp.session_id.version == 5


def test_ip_and_user_agent_cannot_be_confused() -> None:
    # Different splits of the same characters must not collide.
    assert fingerprint_v1(ip_address("1.2.3.4"), "5") != fingerprint_v1(ip_address("1.2.3.45"), "")


def test_ipv6_is_supported() -> None:
    assert fingerprint_v1(ip_address("2001:db8::1"), "x").world_id.startswith("w_")
