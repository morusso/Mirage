import re

import pytest

from app.engine.world_data import (
    PRODUCT_COUNT,
    USER_COUNT,
    base_product,
    base_products,
    base_user,
    base_users,
)

WORLD = "w_0123456789abcdef"
OTHER = "w_fedcba9876543210"
ISO = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def test_world_is_reproducible() -> None:
    assert base_users(WORLD) == base_users(WORLD)
    assert base_products(WORLD) == base_products(WORLD)


def test_worlds_differ() -> None:
    assert base_users(WORLD) != base_users(OTHER)
    assert base_products(WORLD) != base_products(OTHER)


def test_an_object_does_not_depend_on_the_others_being_generated() -> None:
    assert base_user(WORLD, 42) == base_users(WORLD)[41]
    assert base_product(WORLD, 17) == base_products(WORLD)[16]


def test_counts_and_ids_are_contiguous() -> None:
    assert [u.id for u in base_users(WORLD)] == list(range(1, USER_COUNT + 1))
    assert [p.id for p in base_products(WORLD)] == list(range(1, PRODUCT_COUNT + 1))


@pytest.mark.parametrize("object_id", [0, -1, USER_COUNT + 1, 1042])
def test_ids_outside_the_base_world_are_absent(object_id: int) -> None:
    assert base_user(WORLD, object_id) is None


@pytest.mark.parametrize("object_id", [0, -1, PRODUCT_COUNT + 1])
def test_product_ids_outside_the_base_world_are_absent(object_id: int) -> None:
    assert base_product(WORLD, object_id) is None


def test_emails_skus_are_unique_and_emails_use_reserved_domains() -> None:
    users, products = base_users(WORLD), base_products(WORLD)

    assert len({u.email for u in users}) == len(users)
    assert len({p.sku for p in products}) == len(products)
    assert all(u.email.endswith((".com", ".org", ".net")) for u in users)
    assert all(u.email.rsplit("@", 1)[1].startswith("example.") for u in users)


def test_roles() -> None:
    roles = {u.id: u.role for u in base_users(WORLD)}

    assert roles[1] == "admin"
    assert roles[10] == "support"
    assert roles[2] == "customer"
    assert list(roles.values()).count("admin") == 1


def test_values_are_well_formed() -> None:
    for user in base_users(WORLD):
        assert ISO.match(user.created_at) and ISO.match(user.last_login)
        assert user.last_login >= user.created_at
        assert re.fullmatch(r"\+1 \d{3}-\d{3}-\d{4}", user.phone)
    for product in base_products(WORLD):
        assert ISO.match(product.created_at)
        assert 4.99 <= product.price <= 299.99
        assert round(product.price, 2) == product.price
        assert 0 <= product.stock <= 500
        assert product.currency == "USD"


def test_pinned_sample_catches_accidental_changes_to_generation() -> None:
    # If this fails after an intended change, every existing world changes with it.
    user, product = base_user(WORLD, 2), base_product(WORLD, 3)

    assert user is not None and product is not None
    assert (user.email, user.phone, user.created_at) == (
        "michael.phillips2@example.org",
        "+1 230-306-1400",
        "2023-09-28T02:59:05Z",
    )
    assert (product.name, product.sku, product.price) == ("Ergonomic Backpack", "SKU-1021", 167.58)
