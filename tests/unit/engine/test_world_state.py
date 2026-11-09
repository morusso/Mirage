from app.engine.world_state import seeded, world_seed


def _draw(world_id: str, namespace: str = "") -> list[str]:
    fake = seeded(world_id, namespace=namespace)
    return [fake.name() for _ in range(5)] + [fake.email() for _ in range(5)]


def test_same_world_yields_the_same_data() -> None:
    assert _draw("w_aaaa") == _draw("w_aaaa")


def test_different_worlds_yield_different_data() -> None:
    assert _draw("w_aaaa") != _draw("w_bbbb")


def test_namespaces_are_independent_streams() -> None:
    assert _draw("w_aaaa", "users") != _draw("w_aaaa", "products")
    assert _draw("w_aaaa", "users") == _draw("w_aaaa", "users")


def test_drawing_elsewhere_does_not_shift_a_stream() -> None:
    expected = _draw("w_aaaa", "users")

    other = seeded("w_aaaa", namespace="products")
    for _ in range(100):
        other.name()

    assert _draw("w_aaaa", "users") == expected


def test_seed_is_stable_across_processes() -> None:
    # Pinned: a change here means every existing world would silently change.
    assert world_seed("w_0123456789abcdef") == 11074898843074542531
