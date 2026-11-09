"""Base users and products of a world, generated from its seed.

Every object is generated from its own seed (world id plus kind plus object id), not
from one running stream. So user 1042 is the same person whether or not users 1 to 1041
were ever generated: a request for one id costs one object, and nothing needs storing
until an attacker changes something (see the delta store).

Which ids exist is fixed: users 1..USER_COUNT and products 1..PRODUCT_COUNT. Any other
id is absent from the base world (it may still exist in the world's delta).
"""

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict

from app.engine.world_state import seeded

USER_COUNT = 50
PRODUCT_COUNT = 60

# Fixed bounds: Faker's relative dates ("-2y") would drift with the wall clock and make
# a world differ from one day to the next.
_USERS_SINCE = datetime(2022, 1, 1, tzinfo=UTC)
_USERS_UNTIL = datetime(2024, 12, 31, tzinfo=UTC)
_PRODUCTS_SINCE = datetime(2023, 1, 1, tzinfo=UTC)
_LAST_LOGIN_UNTIL = datetime(2025, 6, 30, tzinfo=UTC)

# Reserved by RFC 2606: can never be a real mailbox.
_EMAIL_DOMAINS = ("example.com", "example.org", "example.net")

_ADJECTIVES = ("Wireless", "Compact", "Ergonomic", "Premium", "Portable", "Classic", "Smart")
_NOUNS = {
    "electronics": ("Mouse", "Keyboard", "Webcam", "Charger", "Hub"),
    "audio": ("Headphones", "Speaker", "Earbuds", "Microphone"),
    "apparel": ("Jacket", "Hoodie", "Cap", "Backpack"),
    "home": ("Lamp", "Kettle", "Organizer", "Mug"),
    "outdoor": ("Flask", "Tent", "Headlamp"),
    "fitness": ("Yoga Mat", "Dumbbell Set", "Resistance Bands"),
}


class WorldUser(BaseModel):
    model_config = ConfigDict(frozen=True)

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


class WorldProduct(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: int
    name: str
    sku: str
    category: str
    price: float
    currency: str
    stock: int
    created_at: str


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _role(user_id: int) -> str:
    if user_id == 1:
        return "admin"
    return "support" if user_id % 10 == 0 else "customer"


def base_user(world_id: str, user_id: int) -> WorldUser | None:
    """User ``user_id`` of the base world, or None if that id is not part of it."""
    if not 1 <= user_id <= USER_COUNT:
        return None
    fake = seeded(world_id, namespace=f"user:{user_id}")
    first, last = fake.first_name(), fake.last_name()
    created = fake.date_time_between(_USERS_SINCE, _USERS_UNTIL, tzinfo=UTC)
    return WorldUser(
        id=user_id,
        # The id keeps emails unique without a lookup across users (logins match on it).
        email=f"{first}.{last}{user_id}@{fake.random_element(_EMAIL_DOMAINS)}".lower(),
        first_name=first,
        last_name=last,
        role=_role(user_id),
        # North American numbers: area code and exchange never start with 0 or 1.
        phone=f"+1 {fake.random_int(201, 989)}-{fake.random_int(200, 999)}-"
        f"{fake.random_int(0, 9999):04d}",
        city=fake.city(),
        country="US",
        created_at=_iso(created),
        last_login=_iso(fake.date_time_between(created, _LAST_LOGIN_UNTIL, tzinfo=UTC)),
    )


def base_product(world_id: str, product_id: int) -> WorldProduct | None:
    """Product ``product_id`` of the base world, or None if that id is not part of it."""
    if not 1 <= product_id <= PRODUCT_COUNT:
        return None
    fake = seeded(world_id, namespace=f"product:{product_id}")
    category = fake.random_element(tuple(_NOUNS))
    name = f"{fake.random_element(_ADJECTIVES)} {fake.random_element(_NOUNS[category])}"
    return WorldProduct(
        id=product_id,
        name=name,
        sku=f"SKU-{1000 + product_id * 7}",  # unique by construction
        category=category,
        price=fake.random_int(499, 29_999) / 100,
        currency="USD",
        stock=fake.random_int(0, 500),
        created_at=_iso(fake.date_time_between(_PRODUCTS_SINCE, _USERS_UNTIL, tzinfo=UTC)),
    )


def base_users(world_id: str) -> list[WorldUser]:
    return [u for i in range(1, USER_COUNT + 1) if (u := base_user(world_id, i)) is not None]


def base_products(world_id: str) -> list[WorldProduct]:
    return [p for i in range(1, PRODUCT_COUNT + 1) if (p := base_product(world_id, i)) is not None]
