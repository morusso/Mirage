import hashlib
from dataclasses import dataclass
from uuid import UUID, uuid5

from app.capture.client_ip import IPAddress

FINGERPRINT_VERSION = 1

# Fixed namespace so session ids are stable across restarts and deployments.
_SESSION_NAMESPACE = UUID("8d5a3a42-5c1b-4e0a-9d63-2b7a6f0c4e11")


@dataclass(frozen=True)
class Fingerprint:
    world_id: str
    session_id: UUID


def fingerprint_v1(ip: IPAddress, user_agent: str | None) -> Fingerprint:
    """Identify an attacker by client IP + User-Agent.

    The same visitor always maps to the same world. In v1 the session id is derived
    from the same fingerprint (session == world); splitting a world into sessions by
    inactivity is the sessionizer's job. Version 2 will add the JA4 TLS fingerprint.
    """
    material = f"{ip}\n{(user_agent or '').strip()}"
    digest = hashlib.sha256(material.encode()).hexdigest()
    world_id = f"w_{digest[:16]}"
    return Fingerprint(world_id=world_id, session_id=uuid5(_SESSION_NAMESPACE, world_id))
