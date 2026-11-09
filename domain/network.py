from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_network

IPV4_SUBNET_PREFIX = 24
IPV6_SUBNET_PREFIX = 64


def subnet_of(ip: IPv4Address | IPv6Address) -> IPv4Network | IPv6Network:
    """The /24 (IPv4) or /64 (IPv6) containing the address, used as a budget dimension.

    An IPv4-mapped IPv6 address (::ffff:203.0.113.7) is treated as the IPv4 address
    it wraps, so dual-stack listeners do not put one scanner in two different buckets.
    """
    if isinstance(ip, IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    prefix = IPV4_SUBNET_PREFIX if isinstance(ip, IPv4Address) else IPV6_SUBNET_PREFIX
    return ip_network(f"{ip}/{prefix}", strict=False)
