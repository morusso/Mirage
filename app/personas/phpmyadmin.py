"""phpMyAdmin bait: the login page scanners look for under a handful of common prefixes.

The login always fails, with the message a real server gives (MySQL "Access denied").
The submitted username is only template context and is HTML-escaped. Credentials are
not stored yet (the credentials_seen table arrives in stage 4).
"""

from urllib.parse import parse_qs

from fastapi import APIRouter, Depends, Request, Response
from markupsafe import Markup

from app.engine.templates import render_template
from app.personas.base import PersonaConfig, answer_head_like_get, persona_dependency

PHPMYADMIN_PERSONA = PersonaConfig(
    name="phpmyadmin", server="Apache/2.4.58 (Debian)", powered_by="PHP/8.2.18"
)

PMA_VERSION = "5.2.1"
# Case matters on Linux, and scanners try all of these.
PREFIXES = ("/phpmyadmin", "/phpMyAdmin", "/pma", "/PMA", "/mysql", "/myadmin", "/dbadmin")
MAX_FORM_BYTES = 8192
# Fixed: a per-request token would make identical requests differ across a session.
SESSION_ID = "c1e0d8a54b7f9a3e2d6c8b0a1f4e7d95"
TOKEN = "Zm5jT3pkLmpWTn5HSHxFPQ"  # noqa: S105 (bait page token, not a secret)

_ACCESS_DENIED = Markup("Access denied for user '{}'@'localhost' (using password: {})")
_NO_USER = Markup("Cannot log in to the MySQL server")

inner = APIRouter(include_in_schema=False)


def _login_page(base: str, *, username: str = "", error: Markup | None = None) -> Response:
    page = render_template(
        "phpmyadmin/login.html",
        base=base,
        username=username,
        error=error,
        session=SESSION_ID,
        token=TOKEN,
    )
    return Response(
        content=page,
        headers={
            "content-type": "text/html; charset=utf-8",
            "set-cookie": f"phpMyAdmin={SESSION_ID}; path={base}/; HttpOnly; SameSite=Strict",
            "cache-control": "no-store, no-cache, must-revalidate, max-age=0",
        },
    )


async def _form(request: Request) -> dict[str, str]:
    raw = (await request.body())[:MAX_FORM_BYTES].decode("utf-8", errors="replace")
    return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}


def _register(base: str) -> None:
    @inner.get(base, name=f"pma-root-{base}")
    @inner.get(f"{base}/", name=f"pma-slash-{base}")
    @inner.get(f"{base}/index.php", name=f"pma-index-{base}")
    async def login_page() -> Response:
        return _login_page(base)

    @inner.post(f"{base}/index.php", name=f"pma-login-{base}")
    async def login_submit(request: Request) -> Response:
        form = await _form(request)
        username = form.get("pma_username", "")
        if not username:
            return _login_page(base, error=_NO_USER)
        using = "YES" if form.get("pma_password") else "NO"
        return _login_page(base, username=username, error=_ACCESS_DENIED.format(username, using))

    @inner.get(f"{base}/README", name=f"pma-readme-{base}")
    async def readme() -> Response:
        return Response(
            content=render_template("phpmyadmin/readme.txt", version=PMA_VERSION),
            headers={"content-type": "text/plain"},
        )


for _base in PREFIXES:
    _register(_base)

# Routes are copied on include, so this must come after all route definitions.
answer_head_like_get(inner)
router = APIRouter(dependencies=[Depends(persona_dependency(PHPMYADMIN_PERSONA))])
router.include_router(inner)
