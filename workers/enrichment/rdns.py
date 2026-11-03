import asyncio
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Protocol

import dns.asyncresolver
import dns.exception
import dns.resolver


class PtrResolver(Protocol):
    async def resolve_address(self, ipaddr: str, *args: Any, **kwargs: Any) -> Any: ...


class ReverseDns:
    """Reverse DNS (PTR) name of an IP address, or None when there is none.

    Attackers control their own PTR records and some name servers are slow or
    unreachable, so every lookup has a hard deadline and every failure is reported
    as "no name" rather than raised: enrichment must never stall the pipeline.
    The returned name is attacker-controlled text; treat it as data.
    """

    def __init__(self, timeout_s: float = 2.0, resolver: PtrResolver | None = None) -> None:
        self._timeout_s = timeout_s
        if resolver is None:
            default = dns.asyncresolver.Resolver()
            default.lifetime = timeout_s  # total budget across retries and servers
            resolver = default
        self._resolver = resolver

    async def lookup(self, ip: IPv4Address | IPv6Address) -> str | None:
        try:
            # The resolver enforces its own lifetime; this is the backstop for a
            # resolver that does not (or a stuck socket).
            async with asyncio.timeout(self._timeout_s):
                answer = await self._resolver.resolve_address(str(ip))
        except (TimeoutError, dns.exception.DNSException):
            return None
        for record in answer:
            name: str = record.target.to_text().rstrip(".").lower()
            if name:
                return name
        return None
