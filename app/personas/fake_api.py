import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, TypeAdapter

from app.engine.templates import render_template
from app.personas.base import PersonaConfig, answer_head_like_get, persona_dependency
from app.personas.fake_jwt import FAKE_SECRET, issue_token

FAKE_API_PERSONA = PersonaConfig(name="fake_api", server="nginx/1.24.0", powered_by="Express")

FIXTURES_DIR = Path(__file__).parent / "fixtures"
DEFAULT_PAGE_SIZE = 10
MAX_PAGE_SIZE = 50
TOKEN_TTL_S = 3600

# Passwords commonly found in credential-stuffing lists; anything else is rejected.
WEAK_PASSWORDS = frozenset(
    {"password", "password1", "123456", "12345678", "qwerty", "letmein", "admin", "admin123"}
)


class Product(BaseModel):
    id: int
    name: str
    sku: str
    category: str
    price: float
    currency: str
    stock: int
    created_at: str


class User(BaseModel):
    id: int
    email: str
    first_name: str
    last_name: str
    role: str
    phone: str
    city: str
    country: str
    created_at: str
    last_login: str


PRODUCTS: list[Product] = TypeAdapter(list[Product]).validate_python(
    json.loads((FIXTURES_DIR / "products.json").read_text())
)
_PRODUCTS_BY_ID = {p.id: p for p in PRODUCTS}

USERS: list[User] = TypeAdapter(list[User]).validate_python(
    json.loads((FIXTURES_DIR / "users.json").read_text())
)
_USERS_BY_ID = {u.id: u for u in USERS}
_USERS_BY_EMAIL = {u.email: u for u in USERS}

# Bait secrets. Obviously invented and deliberately NOT shaped like real provider keys
# (AWS, Stripe, ...) so secret scanners do not flag this repository. JWT_SECRET matches
# the key used to sign tokens in /auth/login so the leaked file is internally consistent.
# TODO(stage 3): replace with per-world canary tokens.
ENV_BAIT_CONTEXT = {
    "host": "shopnest.store",
    "db_host": "10.0.4.12",
    "db_password": "Sh0pN3st-Pr0d#2024",
    "redis_host": "10.0.4.13",
    "redis_password": "r3d1s-c4che-9f2a",
    "jwt_secret": FAKE_SECRET.decode(),
    "smtp_password": "m41l-r3lay-7c1d",
}

SWAGGER_SPEC: dict[str, Any] = json.loads((FIXTURES_DIR / "swagger.json").read_text())

api_router = APIRouter(prefix="/api/v1", include_in_schema=False)
root_router = APIRouter(include_in_schema=False)


def json_response(content: Any, status_code: int = 200) -> Response:
    # Express-style Content-Type (with charset), unlike Starlette's default.
    return JSONResponse(
        content,
        status_code=status_code,
        headers={"content-type": "application/json; charset=utf-8"},
    )


def _int_param(raw: str | None, default: int, *, minimum: int, maximum: int | None = None) -> int:
    """Lenient query parsing: invalid input falls back to the default.

    Declaring typed query params would make FastAPI answer with its own 422
    body, which fingerprints the framework.
    """
    try:
        value = int(raw) if raw is not None else default
    except ValueError:
        return default
    value = max(value, minimum)
    return min(value, maximum) if maximum is not None else value


@api_router.get("/products")
async def list_products(request: Request) -> Response:
    page = _int_param(request.query_params.get("page"), 1, minimum=1)
    limit = _int_param(
        request.query_params.get("limit"), DEFAULT_PAGE_SIZE, minimum=1, maximum=MAX_PAGE_SIZE
    )
    start = (page - 1) * limit
    items = PRODUCTS[start : start + limit]
    return json_response(
        {
            "data": [p.model_dump() for p in items],
            "meta": {"page": page, "limit": limit, "total": len(PRODUCTS)},
        }
    )


@api_router.get("/products/{product_id}")
async def get_product(product_id: str) -> Response:
    product = _PRODUCTS_BY_ID.get(int(product_id)) if product_id.isdecimal() else None
    if product is None:
        return json_response({"error": "Not Found", "message": "Product not found"}, 404)
    return json_response({"data": product.model_dump()})


@api_router.get("/users")
async def list_users() -> Response:
    # Bait: the collection looks protected, which invites probing of /users/{id}.
    response = json_response({"error": "Unauthorized", "message": "Authentication required"}, 401)
    response.headers["www-authenticate"] = "Bearer"
    return response


@api_router.get("/users/{user_id}")
async def get_user(user_id: str) -> Response:
    # Bait (IDOR): intentionally no authentication or ownership check.
    user = _USERS_BY_ID.get(int(user_id)) if user_id.isdecimal() else None
    if user is None:
        return json_response({"error": "Not Found", "message": "User not found"}, 404)
    return json_response({"data": user.model_dump()})


@api_router.post("/auth/login")
async def login(request: Request) -> Response:
    try:
        body = json.loads(await request.body())
    except ValueError:
        body = None
    email = body.get("email") if isinstance(body, dict) else None
    password = body.get("password") if isinstance(body, dict) else None
    if not isinstance(email, str) or not isinstance(password, str) or not email or not password:
        return json_response(
            {"error": "Bad Request", "message": "Email and password are required"}, 400
        )

    user = _USERS_BY_EMAIL.get(email.lower())
    if user is None or password not in WEAK_PASSWORDS:
        # Same response for unknown email and wrong password (no user enumeration here).
        return json_response({"error": "Unauthorized", "message": "Invalid credentials"}, 401)

    token = issue_token(
        {"sub": str(user.id), "email": user.email, "role": user.role}, ttl_s=TOKEN_TTL_S
    )
    return json_response(
        {
            "token": token,
            "token_type": "Bearer",
            "expires_in": TOKEN_TTL_S,
            "user": {"id": user.id, "email": user.email, "role": user.role},
        }
    )


@root_router.get("/swagger.json")
async def swagger_json() -> Response:
    # Bait: an "accidentally" exposed API description that invites targeted probing.
    return json_response(SWAGGER_SPEC)


@root_router.get("/.env")
async def dotenv() -> Response:
    # Bait: a classic misconfiguration, served like a static dotfile (no known extension).
    return Response(
        content=render_template("fake_api/dotenv.env", **ENV_BAIT_CONTEXT),
        headers={"content-type": "application/octet-stream"},
    )


# Routes are copied on include, so this must come after all route definitions.
answer_head_like_get(api_router)
answer_head_like_get(root_router)
router = APIRouter(dependencies=[Depends(persona_dependency(FAKE_API_PERSONA))])
router.include_router(api_router)
router.include_router(root_router)
