"""Leaked repository and config files: /.git/*, wp-config backup, AWS credentials.

Static bait from trusted templates, served like dotfiles on nginx (unknown extension,
so application/octet-stream). Values are invented and deliberately not shaped like real
provider keys, so secret scanners do not flag this repository; the database password is
the one from the fake API's .env so the leaks stay consistent with each other.
TODO(stage 3): replace with per-world canary tokens.
"""

from fastapi import APIRouter, Depends, Response

from app.engine.templates import render_template
from app.personas.base import PersonaConfig, answer_head_like_get, persona_dependency
from app.personas.fake_api import ENV_BAIT_CONTEXT

CONFIG_LEAKS_PERSONA = PersonaConfig(name="config_leaks", server="nginx/1.24.0")

COMMIT = "9c1f3a7e5b2d48601ad9e4f7c3b8a2d61e0f5b94"
GIT_HEAD = "ref: refs/heads/main\n"
PACKED_REFS = f"# pack-refs with: peeled fully-peeled sorted \n{COMMIT} refs/heads/main\n"

_GIT_CONTEXT = {"git_user": "deploy", "git_token": "d3pl0y-t0k3n-81fa"}
_WP_CONTEXT = {
    "db_password": ENV_BAIT_CONTEXT["db_password"],
    "db_host": ENV_BAIT_CONTEXT["db_host"],
    "salt": "sn-w9Qe-71kd-",
}
_AWS_CONTEXT = {
    "access_key_id": "SHOPNEST0PRODKEY01",
    "secret_access_key": "sn/prod/Vq81xTz0LmKd93aPwRb27cYh5EuJf4",
}

_inner = APIRouter(include_in_schema=False)


def _file(content: str) -> Response:
    return Response(content=content, headers={"content-type": "application/octet-stream"})


@_inner.get("/.git/HEAD")
async def git_head() -> Response:
    return _file(GIT_HEAD)


@_inner.get("/.git/config")
async def git_config() -> Response:
    return _file(render_template("leaks/git_config", **_GIT_CONTEXT))


@_inner.get("/.git/logs/HEAD")
async def git_logs_head() -> Response:
    return _file(render_template("leaks/git_logs_head", commit=COMMIT))


@_inner.get("/.git/refs/heads/main")
async def git_ref_main() -> Response:
    return _file(f"{COMMIT}\n")


@_inner.get("/.git/packed-refs")
async def git_packed_refs() -> Response:
    return _file(PACKED_REFS)


@_inner.get("/wp-config.php.bak")
@_inner.get("/wp-config.php~")
@_inner.get("/wp-config.php.old")
async def wp_config_backup() -> Response:
    return _file(render_template("leaks/wp_config.php", **_WP_CONTEXT))


@_inner.get("/.aws/credentials")
async def aws_credentials() -> Response:
    return _file(render_template("leaks/aws_credentials", **_AWS_CONTEXT))


# Routes are copied on include, so this must come after all route definitions.
answer_head_like_get(_inner)
router = APIRouter(dependencies=[Depends(persona_dependency(CONFIG_LEAKS_PERSONA))])
router.include_router(_inner)
