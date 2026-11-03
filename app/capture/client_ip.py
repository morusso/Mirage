from collections.abc import Iterable
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address

IPAddress = IPv4Address | IPv6Address
IPNetwork = IPv4Network | IPv6Network


def _is_trusted(ip: IPAddress, trusted: Iterable[IPNetwork]) -> bool:
    return any(ip in network for network in trusted if network.version == ip.version)


def resolve_client_ip(
    peer: IPAddress,
    forwarded_for: str | None,
    trusted_proxies: Iterable[IPNetwork],
) -> IPAddress:
    """Real client address, honouring X-Forwarded-For only when the peer is a trusted proxy.

    Walks the header from the right (the entries my own proxies appended) and
    returns the first address that is not itself a trusted proxy. Entries further
    left are client-controlled and therefore spoofable, so they are never trusted
    past an untrusted hop. An unparsable entry ends the walk.
    """
    trusted = tuple(trusted_proxies)
    if not forwarded_for or not _is_trusted(peer, trusted):
        return peer

    candidate = peer
    for raw in reversed(forwarded_for.split(",")):
        try:
            hop = ip_address(raw.strip())
        except ValueError:
            break
        candidate = hop
        if not _is_trusted(hop, trusted):
            break
    return candidate
