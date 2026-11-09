"""The fake world one attacker sees: seeded base data plus the changes they made.

A world is identified by ``world_id`` (see ``app.capture.fingerprint``). Its base data,
the products and users the honeypot "has", is not stored: it is generated from a seed
derived from the world id, so the same world always yields the same data and nothing
has to be written to Redis until the attacker changes something.
"""

import hashlib

from faker import Faker

# Faker's locale decides names, cities, phone formats. One locale keeps a world coherent.
LOCALE = "en_US"


def world_seed(world_id: str) -> int:
    """Stable 64-bit seed for a world. Not ``hash()``: that is salted per process."""
    digest = hashlib.sha256(world_id.encode()).digest()
    return int.from_bytes(digest[:8], "big")


def seeded(world_id: str, *, namespace: str = "") -> Faker:
    """A fresh Faker that produces the same sequence every time for this world.

    ``namespace`` separates independent streams within one world ("users", "products"),
    so generating more of one kind never shifts the values of another: user 7 stays user
    7 whatever else was generated first. A new instance per call also means concurrent
    requests cannot interleave draws from a shared generator.
    """
    fake = Faker(LOCALE)
    fake.seed_instance(world_seed(f"{world_id}:{namespace}"))
    return fake
