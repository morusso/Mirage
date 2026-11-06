"""WordPress bait: the paths every scanner tries first (wp-login, xmlrpc, REST users).

Bodies come from trusted templates; attacker input (the submitted username) is only
ever template context and is HTML-escaped. Credentials are not stored yet: that
arrives with the admin persona and the credentials_seen table.
"""

from urllib.parse import parse_qs, quote

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from markupsafe import Markup

from app.engine.templates import render_template
from app.personas.base import PersonaConfig, answer_head_like_get, persona_dependency

WORDPRESS_PERSONA = PersonaConfig(name="wordpress", server="nginx/1.24.0", powered_by="PHP/8.2.18")

WP_VERSION = "6.4.3"
KNOWN_USERS = {"admin": 1}
MAX_FORM_BYTES = 8192

_NO_CACHE = {
    "expires": "Wed, 11 Jan 1984 05:00:00 GMT",
    "cache-control": "no-cache, must-revalidate, max-age=0, no-store, private",
}

# str.format on Markup escapes the argument, so the username cannot inject HTML.
_UNKNOWN_USER = Markup(
    "<strong>Error:</strong> The username <strong>{}</strong> is not registered on this site."
)
_WRONG_PASSWORD = Markup(
    "<strong>Error:</strong> The password you entered for the username "
    "<strong>{}</strong> is incorrect."
)

router_inner = APIRouter(include_in_schema=False)


def _login_page(*, username: str = "", error: Markup | None = None, status: int = 200) -> Response:
    page = render_template("wordpress/login.html", username=username, error=error)
    return Response(
        content=page,
        status_code=status,
        headers={
            "content-type": "text/html; charset=UTF-8",
            "set-cookie": "wordpress_test_cookie=WP%20Cookie%20check; path=/; secure",
            **_NO_CACHE,
        },
    )


async def _form(request: Request) -> dict[str, str]:
    """Parse a urlencoded body by hand (no multipart dependency); bounded and lenient."""
    raw = (await request.body())[:MAX_FORM_BYTES].decode("utf-8", errors="replace")
    return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}


@router_inner.get("/wp-login.php")
async def login_page() -> Response:
    return _login_page()


@router_inner.post("/wp-login.php")
async def login_submit(request: Request) -> Response:
    form = await _form(request)
    username = form.get("log", "")
    if not username:
        return _login_page(error=Markup("<strong>Error:</strong> The username field is empty."))
    if not form.get("pwd"):
        return _login_page(
            username=username,
            error=Markup("<strong>Error:</strong> The password field is empty."),
        )
    message = _UNKNOWN_USER if username.lower() not in KNOWN_USERS else _WRONG_PASSWORD
    error = message.format(username)
    return _login_page(username=username, error=error)


@router_inner.api_route("/wp-admin", methods=["GET", "HEAD"])
@router_inner.api_route("/wp-admin/", methods=["GET", "HEAD"])
async def admin_redirect(request: Request) -> Response:
    target = quote(request.url.path, safe="")
    return Response(
        status_code=302,
        headers={"location": f"/wp-login.php?redirect_to={target}&reauth=1", **_NO_CACHE},
    )


@router_inner.get("/readme.html")
async def readme() -> Response:
    return Response(
        content=render_template("wordpress/readme.html", version=WP_VERSION),
        headers={"content-type": "text/html", "last-modified": "Tue, 06 Feb 2024 17:20:00 GMT"},
    )


@router_inner.get("/xmlrpc.php")
async def xmlrpc_get() -> Response:
    return Response(
        content="XML-RPC server accepts POST requests only.",
        status_code=405,
        headers={"content-type": "text/plain; charset=UTF-8", "allow": "POST"},
    )


@router_inner.post("/xmlrpc.php")
async def xmlrpc_post() -> Response:
    # Every call fails authentication: enough to keep brute-force tooling busy.
    return Response(
        content=render_template("wordpress/xmlrpc_fault.xml"),
        headers={"content-type": "text/xml; charset=UTF-8"},
    )


@router_inner.get("/wp-json/wp/v2/users")
async def rest_users() -> Response:
    users = [
        {
            "id": uid,
            "name": name,
            "url": "",
            "description": "",
            "link": f"/author/{name}/",
            "slug": name,
        }
        for name, uid in KNOWN_USERS.items()
    ]
    return JSONResponse(users, headers={"content-type": "application/json; charset=UTF-8"})


@router_inner.get("/wp-cron.php")
async def wp_cron() -> Response:
    return Response(content="", headers={"content-type": "text/html; charset=UTF-8", **_NO_CACHE})


answer_head_like_get(router_inner)
router = APIRouter(dependencies=[Depends(persona_dependency(WORDPRESS_PERSONA))])
router.include_router(router_inner)
