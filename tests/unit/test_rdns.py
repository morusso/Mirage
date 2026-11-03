import asyncio
from ipaddress import ip_address
from types import SimpleNamespace
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.name
import dns.resolver
import pytest

from workers.enrichment.rdns import ReverseDns


class FakeResolver:
    def __init__(
        self,
        *,
        names: list[str] | None = None,
        error: type[Exception] | None = None,
        delay_s: float = 0.0,
    ) -> None:
        self.names = names or []
        self.error = error
        self.delay_s = delay_s
        self.asked: list[str] = []

    async def resolve_address(self, ipaddr: str, *args: Any, **kwargs: Any) -> Any:
        self.asked.append(ipaddr)
        await asyncio.sleep(self.delay_s)
        if self.error:
            raise self.error()
        return [SimpleNamespace(target=dns.name.from_text(n)) for n in self.names]


async def test_returns_normalized_ptr_name() -> None:
    resolver = FakeResolver(names=["Scanner-1.Example.COM."])

    result = await ReverseDns(resolver=resolver).lookup(ip_address("203.0.113.7"))

    assert result == "scanner-1.example.com"
    assert resolver.asked == ["203.0.113.7"]


async def test_first_name_wins_when_several_ptr_records() -> None:
    resolver = FakeResolver(names=["a.example.com.", "b.example.com."])

    assert await ReverseDns(resolver=resolver).lookup(ip_address("2001:db8::1")) == "a.example.com"


@pytest.mark.parametrize(
    "error",
    [
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.resolver.LifetimeTimeout,
        dns.exception.DNSException,
    ],
)
async def test_dns_failures_give_none(error: type[Exception]) -> None:
    resolver = FakeResolver(error=error)

    assert await ReverseDns(resolver=resolver).lookup(ip_address("203.0.113.7")) is None


async def test_empty_answer_gives_none() -> None:
    assert await ReverseDns(resolver=FakeResolver()).lookup(ip_address("203.0.113.7")) is None


async def test_slow_resolver_is_cut_off_at_the_deadline() -> None:
    resolver = FakeResolver(names=["slow.example.com."], delay_s=5.0)
    rdns = ReverseDns(timeout_s=0.05, resolver=resolver)

    started = asyncio.get_running_loop().time()
    result = await rdns.lookup(ip_address("203.0.113.7"))

    assert result is None
    assert asyncio.get_running_loop().time() - started < 1.0


def test_default_resolver_lifetime_follows_timeout() -> None:
    rdns = ReverseDns(timeout_s=1.5)

    resolver = rdns._resolver
    assert isinstance(resolver, dns.asyncresolver.Resolver)
    assert resolver.lifetime == 1.5
