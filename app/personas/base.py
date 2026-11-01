from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from fastapi import Request

from app.asgi_types import ASGIApp, Message, Receive, Scope, Send

PERSONA_SCOPE_KEY = "mirage.persona"


@dataclass(frozen=True)
class PersonaConfig:
    """Identity a persona presents to the client."""

    name: str
    server: str
    powered_by: str | None = None


DEFAULT_PERSONA = PersonaConfig(name="default", server="nginx/1.24.0")


def persona_dependency(config: PersonaConfig) -> Callable[[Request], Awaitable[None]]:
    """Router dependency that marks the request as handled by the given persona."""

    async def mark_persona(request: Request) -> None:
        request.scope[PERSONA_SCOPE_KEY] = config

    return mark_persona


class PersonaHeadersMiddleware:
    """Sets Server / X-Powered-By on every response according to the active persona.

    The persona is chosen by the router handling the request (see
    persona_dependency); unmatched requests get the default persona.
    """

    def __init__(self, app: ASGIApp, default: PersonaConfig = DEFAULT_PERSONA) -> None:
        self.app = app
        self.default = default

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_persona(message: Message) -> None:
            if message["type"] == "http.response.start":
                persona: PersonaConfig = scope.get(PERSONA_SCOPE_KEY, self.default)
                headers = [
                    (k, v)
                    for k, v in message.get("headers", [])
                    if k.lower() not in (b"server", b"x-powered-by")
                ]
                headers.append((b"server", persona.server.encode("latin-1")))
                if persona.powered_by:
                    headers.append((b"x-powered-by", persona.powered_by.encode("latin-1")))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_persona)
