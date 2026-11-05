import pytest
from fastapi import FastAPI

from app.config import Settings
from app.main import create_app
from scripts.template_coverage import analyze, is_covered, render


@pytest.fixture
def app() -> FastAPI:
    return create_app(Settings(environment="test", internal_server_enabled=False))


@pytest.mark.parametrize(
    ("method", "path", "expected"),
    [
        ("GET", "/api/v1/products", True),
        ("GET", "/api/v1/users/42", True),
        ("get", "/.env", True),
        ("GET", "/nothing-here", False),
        ("POST", "/api/v1/products", False),  # path exists, method does not
    ],
)
def test_is_covered(app: FastAPI, method: str, path: str, expected: bool) -> None:
    assert is_covered(app, method, path) is expected


def test_analyze_counts_requests_not_paths(app: FastAPI) -> None:
    report = analyze(
        app,
        [("GET", "/api/v1/products", 6), ("GET", "/nothing-here", 3), ("GET", "/x", 1)],
    )

    assert (report.total, report.covered) == (10, 6)
    assert report.coverage_pct == 60.0
    assert report.uncovered.most_common(1) == [("/nothing-here", 3)]


def test_empty_report_is_zero_percent(app: FastAPI) -> None:
    assert analyze(app, []).coverage_pct == 0.0


def test_render_escapes_control_characters(app: FastAPI) -> None:
    out = render(analyze(app, [("GET", "/\x1b[31mred", 1)]), top=5)

    assert "\x1b" not in out
    assert "\\x1b" in out
