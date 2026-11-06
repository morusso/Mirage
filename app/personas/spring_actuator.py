"""Spring Boot Actuator bait: /actuator, health, info and env.

Mimics an application with ``management.endpoints.web.exposure.include=*`` and
``show-details=always``, the misconfiguration scanners look for. Property values that
Spring would mask (passwords, secrets) are masked with ``******``, as a real Boot 2.x
does, which is what invites a follow-up request for /actuator/heapdump (not served).
Values are invented and consistent with the other bait (same database host and name).
"""

from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse

from app.personas.base import PersonaConfig, answer_head_like_get, persona_dependency
from app.personas.fake_api import ENV_BAIT_CONTEXT

SPRING_ACTUATOR_PERSONA = PersonaConfig(name="spring_actuator", server="nginx/1.24.0")

ACTUATOR_CONTENT_TYPE = "application/vnd.spring-boot.actuator.v3+json"
MASK = "******"

ENDPOINTS = ("health", "info", "env")

HEALTH: dict[str, Any] = {
    "status": "UP",
    "components": {
        "db": {
            "status": "UP",
            "details": {"database": "MySQL", "validationQuery": "isValid()"},
        },
        "diskSpace": {
            "status": "UP",
            "details": {
                "total": 107374182400,
                "free": 61203283968,
                "threshold": 10485760,
                "path": "/opt/shopnest/.",
                "exists": True,
            },
        },
        "ping": {"status": "UP"},
    },
}

INFO: dict[str, Any] = {
    "app": {"name": "shopnest-api", "description": "ShopNest storefront API", "version": "2.3.1"},
    "build": {
        "artifact": "shopnest-api",
        "name": "shopnest-api",
        "version": "2.3.1",
        "group": "store.shopnest",
        "time": "2024-01-24T13:02:41.318Z",
    },
}


def _source(name: str, properties: dict[str, str]) -> dict[str, Any]:
    return {"name": name, "properties": {k: {"value": v} for k, v in properties.items()}}


ENV: dict[str, Any] = {
    "activeProfiles": ["prod"],
    "propertySources": [
        _source(
            "systemProperties",
            {
                "java.version": "17.0.10",
                "java.vendor": "Eclipse Adoptium",
                "os.name": "Linux",
                "os.arch": "amd64",
                "user.dir": "/opt/shopnest",
                "user.name": "shopnest",
            },
        ),
        _source(
            "applicationConfig: [classpath:/application-prod.yml]",
            {
                "server.port": "8080",
                "spring.datasource.url": f"jdbc:mysql://{ENV_BAIT_CONTEXT['db_host']}:3306/shopnest",
                "spring.datasource.username": "shopnest",
                "spring.datasource.password": MASK,
                "spring.redis.host": ENV_BAIT_CONTEXT["redis_host"],
                "spring.redis.password": MASK,
                "jwt.secret": MASK,
                "management.endpoints.web.exposure.include": "*",
                "management.endpoint.health.show-details": "always",
            },
        ),
    ],
}

_inner = APIRouter(include_in_schema=False)


def _json(content: Any) -> Response:
    return JSONResponse(content, headers={"content-type": ACTUATOR_CONTENT_TYPE})


def _base_url(request: Request) -> str:
    scheme = request.headers.get("x-forwarded-proto") or request.url.scheme
    if scheme not in ("http", "https"):
        scheme = "https"
    return f"{scheme}://{request.headers.get('host', 'localhost')}/actuator"


@_inner.get("/actuator")
@_inner.get("/actuator/")
async def index(request: Request) -> Response:
    base = _base_url(request)
    links = {"self": {"href": base, "templated": False}}
    links.update({name: {"href": f"{base}/{name}", "templated": False} for name in ENDPOINTS})
    return _json({"_links": links})


@_inner.get("/actuator/health")
async def health() -> Response:
    return _json(HEALTH)


@_inner.get("/actuator/info")
async def info() -> Response:
    return _json(INFO)


@_inner.get("/actuator/env")
async def env() -> Response:
    return _json(ENV)


# Routes are copied on include, so this must come after all route definitions.
answer_head_like_get(_inner)
router = APIRouter(dependencies=[Depends(persona_dependency(SPRING_ACTUATOR_PERSONA))])
router.include_router(_inner)
