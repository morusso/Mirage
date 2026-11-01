import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, TypeAdapter

from app.personas.base import PersonaConfig, persona_dependency

FAKE_API_PERSONA = PersonaConfig(name="fake_api", server="nginx/1.24.0", powered_by="Express")

FIXTURES_DIR = Path(__file__).parent / "fixtures"
DEFAULT_PAGE_SIZE = 10
MAX_PAGE_SIZE = 50


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

router = APIRouter(
    prefix="/api/v1",
    dependencies=[Depends(persona_dependency(FAKE_API_PERSONA))],
    include_in_schema=False,
)


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


@router.get("/products")
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


@router.get("/products/{product_id}")
async def get_product(product_id: str) -> Response:
    product = _PRODUCTS_BY_ID.get(int(product_id)) if product_id.isdecimal() else None
    if product is None:
        return json_response({"error": "Not Found", "message": "Product not found"}, 404)
    return json_response({"data": product.model_dump()})


@router.get("/users")
async def list_users() -> Response:
    # Bait: the collection looks protected, which invites probing of /users/{id}.
    response = json_response({"error": "Unauthorized", "message": "Authentication required"}, 401)
    response.headers["www-authenticate"] = "Bearer"
    return response


@router.get("/users/{user_id}")
async def get_user(user_id: str) -> Response:
    # Bait (IDOR): intentionally no authentication or ownership check.
    user = _USERS_BY_ID.get(int(user_id)) if user_id.isdecimal() else None
    if user is None:
        return json_response({"error": "Not Found", "message": "User not found"}, 404)
    return json_response({"data": user.model_dump()})
